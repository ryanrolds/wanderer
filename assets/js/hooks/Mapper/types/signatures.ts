export type SystemSignature = {
  eve_id: string;
  kind: string;
  name: string;
  description?: string;
  group: string;
  updated_at?: string;
};

export enum SignatureGroup {
  GasSite = 'Gas Site',
  RelicSite = 'Relic Site',
  DataSite = 'Data Site',
  OreSite = 'Ore Site',
  CombatSite = 'Combat Site',
  Wormhole = 'Wormhole',
  CosmicSignature = 'Cosmic Signature',
}

export type GroupType = {
  id: string;
  icon: string;
  w: number;
  h: number;
};
