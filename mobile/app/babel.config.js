module.exports = function (api) {
    api.cache(true);
    return {
        presets: ['babel-preset-expo'],
        plugins: [
            'react-native-reanimated/plugin',
            [
                'module-resolver',
                {
                    root: ['./src'],
                    extensions: ['.ios.js', '.android.js', '.js', '.ts', '.tsx', '.json'],
                    alias: {
                        '@': './src',
                        '@components': './src/components',
                        '@services': './src/services',
                        '@hooks': './src/hooks',
                        '@native': './src/native',
                        '@store': './src/store',
                    },
                },
            ],
        ],
    };
};
