  import { Request, Response, NextFunction } from "express";
  import jwt from "jsonwebtoken";
  import { verifyAccessToken } from "../utils/jwt";
  import { IJwtPayload } from "../models/JwtPayload";


  export interface AuthRequest extends Request {
    user?: IJwtPayload;
  }

  export const authenticateToken = (
    req: AuthRequest,
    res: Response,
    next: NextFunction
  ) => {

    const authHeader = req.headers["authorization"]; // Para leer el header de la peticion, la parte de Authorization

    const token = authHeader && authHeader.split(" ")[1]; // Aqui separa el token del header

    if (!token) {
      return res.status(401).json({ message: "Token requerido" }); // Si no hay token, retorna un error 401 (Unauthorized)
    }

    try {
      const decoded = verifyAccessToken(token); // Verifica el access token
      req.user = decoded;
      next(); // Si todo esta bien, pasa a la siguiente ruta
    } catch (err: any) {
      if (err instanceof jwt.TokenExpiredError) {
        return res.status(401).json({ message: "Access token expirado" });
      }

      return res.status(401).json({ message: "Token inválido" });
    }
  };

  export const authorizeRoles = (...roles: ('admin' | 'user')[]) => {
    return (req: AuthRequest, res: Response, next: NextFunction) => {
      // Verifica que el usuario este autenticado 
      if (!req.user) {
        return res.status(401).json({ message: "No autenticado" });
      }
      // Verifica que el rol del usuario este permitidos
      if (!roles.includes(req.user.rol)) {
        return res.status(403).json({ message: "Acceso denegado" });
      }
      next();
    };
  };