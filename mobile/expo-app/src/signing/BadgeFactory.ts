/**
 * BadgeFactory - Creates visual Vouch badges for signed images
 * 
 * Features:
 * - QR code with verification shortlink
 * - Visual badge overlay (checkmark)
 * - Configurable position (default: bottom-right)
 */

export type BadgePosition =
    | 'top-left'
    | 'top-right'
    | 'bottom-left'
    | 'bottom-right'
    | 'center-bottom';

export interface BadgeOptions {
    position?: BadgePosition;
    size?: number;           // Badge size in pixels
    opacity?: number;        // 0-1
    includeQR?: boolean;     // Include QR code
    includeCheckmark?: boolean; // Include checkmark overlay
    verifyUrl?: string;      // Verification URL for QR
    padding?: number;        // Padding from edge
}

export interface BadgeResult {
    imageWithBadge: string;  // Base64 encoded image
    qrCodeData?: string;     // QR code data URL
    verifyUrl: string;
}

const DEFAULT_OPTIONS: Required<BadgeOptions> = {
    position: 'bottom-right',
    size: 64,
    opacity: 0.9,
    includeQR: true,
    includeCheckmark: true,
    verifyUrl: 'https://vch.sh/',
    padding: 16,
};

/**
 * Calculate badge position coordinates
 */
export function calculatePosition(
    imageWidth: number,
    imageHeight: number,
    badgeSize: number,
    position: BadgePosition,
    padding: number
): { x: number; y: number } {
    const positions = {
        'top-left': { x: padding, y: padding },
        'top-right': { x: imageWidth - badgeSize - padding, y: padding },
        'bottom-left': { x: padding, y: imageHeight - badgeSize - padding },
        'bottom-right': { x: imageWidth - badgeSize - padding, y: imageHeight - badgeSize - padding },
        'center-bottom': { x: (imageWidth - badgeSize) / 2, y: imageHeight - badgeSize - padding },
    };

    return positions[position];
}

/**
 * Generate verification URL for QR code
 */
export function generateVerifyUrl(signatureHash: string, baseUrl: string = 'https://vch.sh'): string {
    return `${baseUrl.replace(/\/$/, '')}/${signatureHash.slice(0, 8)}`;
}

/**
 * BadgeFactory class
 * 
 * Usage:
 * ```typescript
 * const factory = new BadgeFactory({ position: 'bottom-right' });
 * const result = await factory.addBadge(imageBase64, signatureHash);
 * ```
 */
export class BadgeFactory {
    private options: Required<BadgeOptions>;

    constructor(options: BadgeOptions = {}) {
        this.options = { ...DEFAULT_OPTIONS, ...options };
    }

    /**
     * Add Vouch badge to image
     * 
     * @param imageBase64 - Base64 encoded source image
     * @param signatureHash - Hash of the signature for QR code
     * @returns BadgeResult with badged image and verify URL
     */
    async addBadge(imageBase64: string, signatureHash: string): Promise<BadgeResult> {
        const verifyUrl = generateVerifyUrl(signatureHash, this.options.verifyUrl);

        // In React Native, we would use:
        // - react-native-qrcode-svg for QR generation
        // - react-native-canvas for image composition

        // For now, return placeholder
        return {
            imageWithBadge: imageBase64, // Would be modified image
            qrCodeData: signatureHash,
            verifyUrl,
        };
    }

    /**
     * Update position for Badge Studio customization
     */
    setPosition(position: BadgePosition): void {
        this.options.position = position;
    }

    /**
     * Get current configuration
     */
    getConfig(): Required<BadgeOptions> {
        return { ...this.options };
    }
}

export default BadgeFactory;
