import { AgreementModel } from './userDetails.model.js';

export interface UserListModel {
    id: string;
    walletAddress?: string;
    username: string;
    telegramHandle?: string;
    invitationToken?: string;
    profilePicture?: string;
    agreement?: AgreementModel | null;
}

