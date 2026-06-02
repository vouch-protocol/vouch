const {
  AndroidConfig,
  createRunOncePlugin,
} = require('expo/config-plugins');

const pkg = require('./package.json');

/**
 * Expo config plugin for @vouch-protocol-official/expo-sonic.
 *
 * Ensures the consuming app declares RECORD_AUDIO (required for real-time
 * watermark detection from the microphone). Add to app.json:
 *
 *   { "expo": { "plugins": ["@vouch-protocol-official/expo-sonic"] } }
 */
const withVouchSonic = (config) => {
  config = AndroidConfig.Permissions.withPermissions(config, [
    'android.permission.RECORD_AUDIO',
  ]);
  return config;
};

module.exports = createRunOncePlugin(withVouchSonic, pkg.name, pkg.version);
