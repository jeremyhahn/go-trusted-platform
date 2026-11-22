export const ZONE_RESTART_NOTICE = 'The change applies at the next daemon restart.';

export type ZoneChangeVerb = 'created' | 'updated' | 'deleted';

export interface ZoneChangeToast {
  title: string;
  description?: string;
  variant: 'success';
}

/** The success toast for a zone change; the server's restart_required adds the restart notice. */
export function zoneChangeToast(verb: ZoneChangeVerb, restartRequired?: boolean): ZoneChangeToast {
  const title = `Zone ${verb}`;
  return restartRequired
    ? { title, description: ZONE_RESTART_NOTICE, variant: 'success' }
    : { title, variant: 'success' };
}
