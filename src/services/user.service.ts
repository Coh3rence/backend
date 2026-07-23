import { v4 as uuidv4 } from 'uuid';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { CreateUserModel } from '../models/user/userRegistration.model.js';
import { injectable } from 'inversify';
import { CreatedResponseModel } from '../models/response_models/created_response_model.js';
import { ResponseModel } from '../models/response_models/response_model.js';
import { SiweMessage } from 'siwe';
import { UserResponseModel } from '../models/user/userDetails.model.js';
import { EmailService } from './email.service.js';
import { AppDataSource } from '../data-source.js';
import { TeamPointsService } from './teamPoints.service.js';
import {
    ContributorRoundCompensation,
    Invitation,
    Organization,
    User,
    WalletNonce
} from '../entities/index.js';

dotenv.config();  // Load the environment variables from .env

/**
 * Internal control-flow error for registerUser: a validation failure raised
 * inside the registration transaction so it rolls back the (possibly already
 * consumed) invite token, while carrying the HTTP status to surface to the caller.
 * A tagged Error (not a subclass) to keep this file to a single class (tslint
 * max-classes-per-file).
 */
type RegisterError = Error & { status: number };

function registerError(message: string, status: number): RegisterError {
    return Object.assign(new Error(message), { status, name: 'RegisterError' });
}

function isRegisterError(err: unknown): err is RegisterError {
    return err instanceof Error && err.name === 'RegisterError'
        && typeof (err as { status?: unknown }).status === 'number';
}

/** MySQL duplicate-entry (unique-constraint) violation, as wrapped by TypeORM. */
function isDuplicateEntryError(err: unknown): boolean {
    const driver = (err as { driverError?: { code?: string; errno?: number } })?.driverError;
    const e = (driver ?? err) as { code?: string; errno?: number } | null;
    return e?.code === 'ER_DUP_ENTRY' || e?.errno === 1062;
}


@injectable()
export class UserService {

    private userRepository;
    private invitationRepository;
    private walletNonceRepository;

    constructor(private emailService: EmailService, private teamPointsService: TeamPointsService) {
        this.userRepository = AppDataSource.getRepository(User);
        this.invitationRepository = AppDataSource.getRepository(Invitation);
        this.walletNonceRepository = AppDataSource.getRepository(WalletNonce);
    }
    /**
     * Register a new user using the invitation token
     * @param token - Invitation token
     * @param userData - User's registration data
     * @returns the registered user
     */
    public async registerUser(
        userData: CreateUserModel
    ): Promise<ResponseModel<CreatedResponseModel | null>> {

        // Fast, friendly pre-checks so the common duplicate case returns a clean 400
        // before we touch the token. These findOnes are NOT the real guard, though: a
        // concurrent signup can slip between the check and the insert, so the DB unique
        // constraints on address+email (user.model.ts) are the source of truth and are
        // caught as a duplicate-entry violation inside the transaction below.
        const existingUser = await this.userRepository
            .findOne({ where: { address: userData.walletAddress?.toLowerCase() } });
        if (existingUser) {
            return ResponseModel.createError(new Error('User already registered'), 400);
        }

        const userByEmail = await this.userRepository.findOne({ where: { email: userData.email } });
        if (userByEmail) {
            return ResponseModel.createError(new Error('Email already registered'), 400);
        }

        try {
            // Consume the invite and create the user in ONE transaction: if the user
            // insert fails (e.g. a racing signup trips the unique address/email
            // constraint), the whole thing rolls back and the single-use token is NOT
            // burned — the contributor can retry with the same link.
            const createdUserId = await AppDataSource.transaction(async (manager) => {
                let organization: Organization | null = null;

                if (userData.invitationToken) {
                    // Existence lookup is for messaging only (distinguish "unknown token"
                    // from "already used up"); the atomic UPDATE below is authoritative.
                    const invitation = await manager.getRepository(Invitation).findOne({
                        where: { token: userData.invitationToken },
                        relations: ['organization']
                    });
                    if (!invitation) {
                        throw registerError('Invalid or expired invitation token.', 400);
                    }

                    // Atomic single-use consume: increment only while the row is still
                    // active and under its limit, flipping isActive off on the final use.
                    // Because the guard and the increment happen in one UPDATE, two
                    // concurrent redemptions of a usageLimit:1 token can't both win —
                    // exactly one of them affects a row.
                    const consumed = await manager.getRepository(Invitation)
                        .createQueryBuilder()
                        .update(Invitation)
                        // NB: MySQL evaluates SET assignments left-to-right and later
                        // expressions see the already-updated column, so by the time the
                        // isActive CASE runs, usageCount is ALREADY incremented — the guard
                        // is `usageCount >= usageLimit` (not `+ 1`), else a multi-use token
                        // would deactivate one redemption early and lock out the last user.
                        .set({
                            usageCount: () => 'usageCount + 1',
                            isActive: () => 'CASE WHEN usageCount >= usageLimit THEN false ELSE isActive END'
                        })
                        .where('token = :token AND isActive = true AND usageCount < usageLimit', {
                            token: userData.invitationToken
                        })
                        .execute();

                    if (consumed.affected !== 1) {
                        throw registerError(
                            'This invitation link has already been used by the maximum number of users.',
                            400
                        );
                    }

                    organization = invitation.organization;
                }

                const user = new User();
                user.address = userData.walletAddress!.toLowerCase();
                user.username = userData.username;
                user.email = userData.email;
                user.telegramHandle = userData.telegramHandle;
                user.invitationToken = userData.invitationToken;
                user.profilePicture = userData.profilePicture;
                if (organization) {
                    user.organization = organization;
                }

                const saved = await manager.getRepository(User).save(user);
                return saved.id;
            });

            // Side effects only after the transaction commits, so a failed email
            // never rolls back a valid registration (and vice versa).
            this.emailService.sendCongratsOnRegistration(userData.email, userData.username);

            return ResponseModel.createSuccess({ id: createdUserId });
        } catch (err) {
            if (isRegisterError(err)) {
                return ResponseModel.createError(new Error(err.message), err.status);
            }
            // A racing signup slipped past the pre-checks and hit the unique
            // address/email constraint — surface a clean 400 instead of an uncaught
            // 500. The token consume was rolled back with the transaction.
            if (isDuplicateEntryError(err)) {
                return ResponseModel.createError(new Error('User already registered'), 400);
            }
            throw err;
        }
    }

    public async getByWalletAddress(walletAddress: string): Promise<ResponseModel<UserResponseModel | null>> {

        const user = await this.userRepository.findOne({
            where: { address: walletAddress.toLowerCase() },
            relations: ['agreement', 'organization']
        });

        const isAdmin = await this.teamPointsService.isAdmin(walletAddress);

        if (!user) {
            return ResponseModel.createError(new Error('User not found'), 404);
        }

        const contributionsRepo = AppDataSource.getRepository(ContributorRoundCompensation);
        const contributions = await contributionsRepo.find({ where: { contributor: { id: user.id } } });
        let totalFiat = 0;
        if (contributions.length > 0) {
            totalFiat = contributions.reduce((acc, curr) => acc + +curr.fiat, 0);
        }

        const responseModel: UserResponseModel = {
            id: user.id,
            walletAddress: user.address,
            username: user.username,
            email: user.email,
            telegramHandle: user.telegramHandle,
            profilePicture: user.profilePicture,
            isAdmin,
            totalFiat,
            organization: user.organization && {
                id: user.organization!.id,
                logo: user.organization!.logo,
                name: user.organization!.name
            },
            agreement: user.agreement && {
                id: user.agreement.id,
                marketRate: user.agreement.marketRate,
                roleName: user.agreement.roleName,
                responsibilities: user.agreement.responsibilities,
                fiatRequested: user.agreement.fiatRequested,
                commitment: user.agreement.commitment
            }
        };

        return ResponseModel.createSuccess(responseModel);
    }
    public async requestNonce(walletAddress: string): Promise<ResponseModel<{ nonce: string } | null>> {
        const nonce = uuidv4();

        // Find the existing WalletNonce record by address
        let walletNonce = await this.walletNonceRepository.findOne({ where: { address: walletAddress } });

        if (walletNonce) {
            walletNonce.nonce = nonce;
            walletNonce.createdAt = new Date(); // Reset creation time
        } else {
            // Create a new WalletNonce entity if it doesn't exist
            walletNonce = this.walletNonceRepository.create({
                address: walletAddress,
                nonce
            });
        }

        await this.walletNonceRepository.save(walletNonce);

        // Return the generated nonce
        return ResponseModel.createSuccess({ nonce });
    }

    public async verifySignature(message: any, signature: string): Promise<ResponseModel<any | null>> {

        const siweMessage = new SiweMessage(message);
        try {
            const res = await siweMessage.verify({ signature });
            if (!res) {
                return ResponseModel.createError(new Error('Invalid signature'), 403);
            }

            const userToEncode = { walletAddress: message.address } as any;
            const token = jwt.sign(userToEncode, process.env.JWT_SECRET!, { expiresIn: '168h' });
            return ResponseModel.createSuccess({ token }, 200);
        } catch (error: any) {
            return ResponseModel.createError(error, 403);
        }
    }
}
