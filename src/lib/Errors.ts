/**
 *  Copyright 2025 Angus.Fenying <fenying@litert.org>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/**
 * The error class for signatures.
 */
export abstract class SignatureError extends Error {

    public constructor(
        /**
         * The name of the error.
         */
        name: string,
        /**
         * The message of the error.
         */
        message: string,
        public readonly ctx: Record<string, unknown> = {},
        /**
         * The metadata of the error.
         */
        public readonly origin: unknown = null
    ) {

        super(message);
        this.name = name;
    }
}

export const E_NO_KEY_PROVIDED = class extends SignatureError {

    public constructor(ctx: Record<string, unknown> = {}, origin?: unknown) {

        super(
            'no_key_provided',
            'At least a private key or a public key must be provided.',
            ctx,
            origin,
        );
    }
};

export const E_INVALID_PUBLIC_KEY = class extends SignatureError {

    public constructor(ctx: Record<string, unknown> = {}, origin?: unknown) {

        super(
            'invalid_public_key',
            'The public key provided is invalid.',
            ctx,
            origin,
        );
    }
};

export const E_INVALID_PRIVATE_KEY = class extends SignatureError {

    public constructor(ctx: Record<string, unknown> = {}, origin?: unknown) {

        super(
            'invalid_private_key',
            'The private key provided is invalid.',
            ctx,
            origin,
        );
    }
};

export const E_KEY_PAIR_MISMATCH = class extends SignatureError {

    public constructor(ctx: Record<string, unknown> = {}, origin?: unknown) {

        super(
            'key_pair_mismatch',
            'The private key and public key do not match.',
            ctx,
            origin,
        );
    }
};

export const E_NO_PRIVATE_KEY = class extends SignatureError {

    public constructor(ctx: Record<string, unknown> = {}, origin?: unknown) {

        super(
            'no_private_key',
            'The private key is not provided.',
            ctx,
            origin,
        );
    }
};

export const E_NO_PUBLIC_KEY = class extends SignatureError {

    public constructor(ctx: Record<string, unknown> = {}, origin?: unknown) {

        super(
            'no_public_key',
            'The public key is not provided.',
            ctx,
            origin,
        );
    }
};

export const E_NOT_IMPLEMENTED = class extends SignatureError {

    public constructor(ctx: Record<string, unknown> = {}, origin?: unknown) {

        super(
            'not_implemented',
            'The requested feature is not implemented.',
            ctx,
            origin,
        );
    }
};

export const E_SIGN_FAILED = class extends SignatureError {

    public constructor(ctx: Record<string, unknown> = {}, origin?: unknown) {

        super(
            'sign_failed',
            'The signing operation failed.',
            ctx,
            origin,
        );
    }
};

export const E_VERIFY_FAILED = class extends SignatureError {

    public constructor(ctx: Record<string, unknown> = {}, origin?: unknown) {

        super(
            'verify_failed',
            'The verification operation failed.',
            ctx,
            origin,
        );
    }
};
