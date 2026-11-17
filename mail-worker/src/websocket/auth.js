import permService from '../service/perm-service';

export async function canWatchAllEmail(env, user) {
	if (!user?.userId) return false;
	if (user.email === env.admin) return true;
	return (await permService.userPermKeys({ env }, user.userId)).includes('all-email:query');
}
