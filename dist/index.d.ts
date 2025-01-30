declare const DiscordClientInterface: {
    start: (runtime: any) => Promise<any>;
    stop: (runtime: any) => Promise<void>;
    config: {
        pluginType: string;
        pluginParameters: {
            DISCORD_API_TOKEN: {
                type: string;
            };
        };
        optionalPluginDependencies: {
            "@elizaos/service-transcription": string;
        };
    };
};

export { DiscordClientInterface, DiscordClientInterface as default };
