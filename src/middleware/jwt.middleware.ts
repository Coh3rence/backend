import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';

/**
 * Service-account auth for the HR Agent bot bridge. A shared secret
 * (X-Service-Key header === SERVICE_API_KEY) stands in for a 7-day SIWE JWT, so
 * the bot can create agreements unattended without holding a wallet key or
 * rotating tokens weekly. On a match we impersonate a designated existing org
 * admin by address (SERVICE_ADMIN_WALLET) — every downstream handler identifies
 * the actor solely by req.user.walletAddress. Fails closed: if either env is
 * unset, or the header is missing/mismatched, returns false so normal Bearer
 * auth proceeds.
 */
export const serviceKeyAuth = (req: Request): boolean => {
    const expected = process.env.SERVICE_API_KEY;
    const wallet = process.env.SERVICE_ADMIN_WALLET;
    const provided = req.headers['x-service-key'];

    if (!expected || !wallet || typeof provided !== 'string' || !provided) {
        return false;
    }

    const a = Buffer.from(provided);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
        return false;
    }

    (req as any).user = { walletAddress: wallet };
    (req as any).isServiceAccount = true;
    return true;
};

export const jwtMiddleware = (req: Request, res: Response, next: NextFunction) => {
    // Bot service-account path (no expiry, no wallet key). See serviceKeyAuth.
    if (serviceKeyAuth(req)) {
        return next();
    }

    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];  // Bearer token

    if (!token) {
        return res.status(401).json({ message: 'Access denied. No token provided.' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        (req as any).user = decoded;  // Attach the decoded token to the request object
        next();  // Continue to the next middleware/route handler
    } catch (err) {
        return res.status(403).json({ message: 'Invalid token.' });
    }
};
