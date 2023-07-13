import { JwtVerifierOptions } from './jwt-verifier';
export interface IssuerMetadata {
    issuer: string;
    jwks_uri: string;
    id_token_signing_alg_values_supported?: string[];
    [key: string]: unknown;
}
export type DiscoverOptions = Required<Pick<JwtVerifierOptions, 'issuerBaseURL' | 'timeoutDuration' | 'cacheMaxAge'>> & Pick<JwtVerifierOptions, 'agent'>;
declare const _default: (opts: DiscoverOptions) => () => Promise<IssuerMetadata>;
export default _default;
