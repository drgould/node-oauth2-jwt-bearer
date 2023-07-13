type QueryLike = Record<string, unknown> & {
    access_token?: string;
};
type BodyLike = QueryLike;
type HeadersLike = Record<string, unknown> & {
    authorization?: string;
    'content-type'?: string;
};
export default function getToken(headers: HeadersLike, query?: QueryLike, body?: BodyLike, urlEncoded?: boolean): string;
export {};
