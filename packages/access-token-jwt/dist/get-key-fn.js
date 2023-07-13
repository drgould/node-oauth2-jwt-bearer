import { createSecretKey } from 'crypto';
import { createRemoteJWKSet } from 'jose';
export default ({ agent, cooldownDuration, timeoutDuration, cacheMaxAge, secret }) => {
    let getKeyFn;
    let prevjwksUri;
    const secretKey = secret && createSecretKey(Buffer.from(secret));
    return (jwksUri) => {
        if (secretKey)
            return () => secretKey;
        if (!getKeyFn || prevjwksUri !== jwksUri) {
            prevjwksUri = jwksUri;
            getKeyFn = createRemoteJWKSet(new URL(jwksUri), {
                agent,
                cooldownDuration,
                timeoutDuration,
                cacheMaxAge,
            });
        }
        return getKeyFn;
    };
};
