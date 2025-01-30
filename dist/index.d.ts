declare const DiscordClientInterface: {
    name: string;
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
    start: (runtime: any) => Promise<any>;
    stop: (runtime: any) => Promise<void>;
};

export { DiscordClientInterface as default };
