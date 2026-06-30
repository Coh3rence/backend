import { Request, Response, NextFunction } from 'express';
import { container } from '../inversify.config.js';
import { TeamPointsService } from '../services/teamPoints.service.js';

export const adminMiddleware = async (req: Request, res: Response, next: NextFunction) => {
  try {
    // Ensure the JWT middleware has run first and set the user
    if (!(req as any).user || !(req as any).user.walletAddress) {
      return res.status(403).json({ message: 'Authentication required' });
    }

    const walletAddress = (req as any).user.walletAddress;

    // Bot service account is pre-trusted as admin: it authenticated via the
    // shared SERVICE_API_KEY and impersonates a designated existing org admin
    // (set in serviceKeyAuth). Skip the on-chain admin lookup for it.
    if ((req as any).isServiceAccount) {
      return next();
    }

    // Dev-only bypass for the on-chain admin gate so the bot bridge can be
    // tested without a deployed TeamPoints contract. Never active in production.
    if (process.env.ADMIN_CHECK_BYPASS === 'true' && process.env.NODE_ENV !== 'production') {
      return next();
    }

    // Use the team points service to check admin status
    const teamPointsService = container.get(TeamPointsService);
    const isAdmin = await teamPointsService.isAdmin(walletAddress);

    if (!isAdmin) {
      return res.status(403).json({ message: 'Not an admin' });
    }

    // If everything passes, continue to the route handler
    next();
  } catch (error) {
    console.error('Error in admin middleware:', error);
    return res.status(500).json({ message: 'Internal Server Error' });
  }
};
