import { DiscordClient } from './discord-client';
import packageJson from "../package.json";

const DiscordClientInterface = {
    name: 'discord',
    config: packageJson.agentConfig,
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
};
export default DiscordClientInterface;