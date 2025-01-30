import { DiscordClient } from './discord-client';
import packageJson from "../package.json";

export const DiscordClientInterface = {
    start: async (runtime: any) => new DiscordClient(runtime) as any,
    stop: async (runtime: any) => {
        try {
            // stop it
            console.log("Stopping discord client", runtime.agentId);
            await runtime.clients.discord.stop();
        } catch (e) {
            console.error("client-discord interface stop error", e);
        }
    },
    config: packageJson.agentConfig,
};
export default DiscordClientInterface;