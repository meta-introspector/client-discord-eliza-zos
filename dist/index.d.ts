import { IAgentRuntime, Character, Client as Client$1 } from '@elizaos/core';
import { Client, MessageReaction, User } from 'discord.js';
import { EventEmitter } from 'events';

declare class DiscordClient extends EventEmitter {
    env: object;
    runtime: IAgentRuntime;
    apiToken: string;
    client: Client;
    character: Character;
    private messageManager;
    private voiceManager;
    constructor(env: any, runtime: IAgentRuntime);
    private setupEventListeners;
    stop(): Promise<void>;
    private onClientReady;
    handleReactionAdd(reaction: MessageReaction, user: User): Promise<void>;
    handleReactionRemove(reaction: MessageReaction, user: User): Promise<void>;
    private handleGuildCreate;
    private handleInteractionCreate;
    private onReady;
}
declare const DiscordClientInterface: Client$1;

export { DiscordClient, DiscordClientInterface, DiscordClientInterface as default };
