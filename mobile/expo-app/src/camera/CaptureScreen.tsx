/**
 * CaptureScreen - Camera with Vouch signing
 * 
 * Signs photos at the moment of capture using device TEE
 */

import React, { useState, useRef } from 'react';
import { View, TouchableOpacity, Text, StyleSheet } from 'react-native';
import { Camera, CameraType } from 'expo-camera';
import { signImage, SignerIdentity } from '../signing/NativeSigner';
import { BadgeFactory } from '../signing/BadgeFactory';

export default function CaptureScreen() {
    const [type, setType] = useState(CameraType.back);
    const [permission, requestPermission] = Camera.useCameraPermissions();
    const [signing, setSigning] = useState(false);
    const cameraRef = useRef<Camera>(null);

    const badgeFactory = new BadgeFactory({ position: 'bottom-right' });

    const handleCapture = async () => {
        if (!cameraRef.current) return;

        setSigning(true);

        try {
            // Capture photo
            const photo = await cameraRef.current.takePictureAsync({
                base64: true,
                exif: true, // Preserve EXIF for "captured" claim
            });

            // Sign immediately
            const identity: SignerIdentity = {
                did: '', // Will be filled by signImage
                displayName: 'User', // TODO: Get from settings
                credentialType: 'FREE',
            };

            const result = await signImage(photo.base64 || '', identity);

            if (result.success && result.signature) {
                // Add visual badge
                const badged = await badgeFactory.addBadge(
                    photo.base64 || '',
                    result.signature
                );

                console.log('✅ Photo signed!');
                console.log('   Chain:', result.chainId);
                console.log('   Verify:', result.verifyUrl);

                // TODO: Save to gallery with sidecar
            }
        } catch (error) {
            console.error('Signing failed:', error);
        } finally {
            setSigning(false);
        }
    };

    if (!permission) {
        return <View />;
    }

    if (!permission.granted) {
        return (
            <View style={styles.container}>
                <Text style={styles.text}>Camera access needed for Vouch</Text>
                <TouchableOpacity onPress={requestPermission} style={styles.button}>
                    <Text style={styles.buttonText}>Grant Permission</Text>
                </TouchableOpacity>
            </View>
        );
    }

    return (
        <View style={styles.container}>
            <Camera style={styles.camera} type={type} ref={cameraRef}>
                <View style={styles.overlay}>
                    <TouchableOpacity
                        style={styles.captureButton}
                        onPress={handleCapture}
                        disabled={signing}
                    >
                        <View style={[styles.captureInner, signing && styles.capturing]} />
                    </TouchableOpacity>
                </View>
            </Camera>
        </View>
    );
}

const styles = StyleSheet.create({
    container: {
        flex: 1,
        backgroundColor: '#000',
    },
    camera: {
        flex: 1,
    },
    overlay: {
        flex: 1,
        justifyContent: 'flex-end',
        alignItems: 'center',
        paddingBottom: 40,
    },
    captureButton: {
        width: 80,
        height: 80,
        borderRadius: 40,
        backgroundColor: 'rgba(255,255,255,0.3)',
        justifyContent: 'center',
        alignItems: 'center',
    },
    captureInner: {
        width: 60,
        height: 60,
        borderRadius: 30,
        backgroundColor: '#fff',
    },
    capturing: {
        backgroundColor: '#4ade80', // Green when signing
    },
    text: {
        color: '#fff',
        fontSize: 18,
        textAlign: 'center',
        marginBottom: 20,
    },
    button: {
        backgroundColor: '#6366f1',
        paddingHorizontal: 24,
        paddingVertical: 12,
        borderRadius: 8,
    },
    buttonText: {
        color: '#fff',
        fontSize: 16,
    },
});
