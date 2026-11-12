import { test } from '@playwright/test';

/**
 * BMC users and web certificate pages (#1720, slice 3 of #1665).
 *
 * One test per BMC operation that has a REST route. EnrollBMC and
 * RestoreFactoryCert have no route yet and stay out of this spec.
 */
test.describe('BMC users and web certificate', () => {
  test.fixme('ListUsers: lists the user slots of a BMC profile', async () => {});
  test.fixme('CreateUser: adds a user from the create dialog', async () => {});
  test.fixme('DeleteUser: deletes a user after the confirm dialog', async () => {});
  test.fixme('SetUserPassword: sets a user password', async () => {});
  test.fixme('SetUserPrivilege: changes a user privilege', async () => {});
  test.fixme('ReplaceWebCertificate: replaces the web certificate after the confirm dialog', async () => {});
});
