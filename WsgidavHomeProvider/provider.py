from wsgidav import fs_dav_provider as fdp, compat, util
import os
import pwd
import grp
import stat
from wsgidav.wsgidav_app import _logger


def mod_to_stat(mod: int) -> int:
    """Convert unix chmod digit-based bitwise permissions to python stat bitwise permissions"""
    mod = str(mod)
    assert 3 <= len(mod) <= 4, "input value must be a 3 or 4 digit integer"
    if len(mod) == 3:
        ur, uw, ux, gr, gw, gx, sr, sw, sx = tuple(
            int(i) & j for i in mod
            for j in [4, 2, 1]
        )
        uid = 0
        gid = 0
        sticky = 0
    else:
        uid, gid, sticky, ur, uw, ux, gr, gw, gx, sr, sw, sx = tuple(
            int(i) & j for i in mod
            for j in [4, 2, 1]
        )

    uid = uid and stat.S_ISUID
    gid = gid and stat.S_ISGID
    sticky = sticky and stat.S_ISVTX
    ur = ur and stat.S_IRUSR
    uw = uw and stat.S_IWUSR
    ux = ux and stat.S_IXUSR
    gr = gr and stat.S_IRGRP
    gw = gw and stat.S_IWGRP
    gx = gx and stat.S_IXGRP
    sr = sr and stat.S_IROTH
    sw = sw and stat.S_IWOTH
    sx = sx and stat.S_IXOTH

    return uid ^ gid ^ sticky ^ ur ^ uw ^ ux ^ gr ^ gw ^ gx ^ sr ^ sw ^ sx


class HomeProvider(fdp.FilesystemProvider):
    def __init__(self, path='~', readonly=False, set_user=True, set_group=True, chmod=640):

        # Here we ensure that set_user uid exists or we convert a string to a uid
        if set_user:
            if isinstance(set_user, int) and not isinstance(set_user, bool):
                assert pwd.getpwuid(set_user)
            elif isinstance(set_user, str):
                set_user = pwd.getpwnam(set_user).pw_uid
        else:
            set_user = os.getuid()

        # And here we do the same thing for the set_group
        if set_group:
            if isinstance(set_group, int) and not isinstance(set_group, bool):
                assert grp.getgrgid(set_group)
            elif isinstance(set_group, str):
                set_group = grp.getgrnam(set_group).gr_gid
        else:
            set_group = os.getgid()

        super().__init__(path, readonly)
        self.root_folder_path = path
        self.uid = set_user
        self.gid = set_group
        self.chmask = mod_to_stat(chmod)

    def _render_root(self, environ):
        """
        Returns the absolute directory of the root_folder_path rendered as though by the authenticated user,
        this allows different users to access their own home directory
        """
        assert environ
        assert 'wsgidav.auth.user_name' in environ
        assert environ.get('wsgidav.auth.realm') == 'PAM(login)'

        return os.path.abspath(
            os.path.expandvars(
                os.path.expanduser(
                    self.root_folder_path.replace('~', '~%s' % environ['wsgidav.auth.user_name'])
                )
            )
        )

    def _loc_to_file_path(self, path, environ=None):
        """
        Same as the parent class, but uses the new _render_root method
        """
        root_path = self._render_root(environ)

        assert root_path is not None
        assert compat.is_native(root_path)
        assert compat.is_native(path)

        path_parts = path.strip("/").split("/")
        file_path = os.path.abspath(
            os.path.join(root_path, *path_parts)
        )
        if not file_path.startswith(root_path):
            raise RuntimeError(
                "Security exception: tried to access file outside root: {}".format(
                    file_path
                )
            )

        # Convert to unicode
        file_path = util.to_unicode_safe(file_path)
        return file_path

    def get_user_group(self, environ) -> (int, int):
        assert environ
        assert 'wsgidav.auth.user_name' in environ
        assert environ.get('wsgidav.auth.realm') == 'PAM(login)'

        if isinstance(self.uid, bool):
            uid = pwd.getpwnam(environ['wsgidav.auth.user_name']).pw_uid
        else:
            uid = self.uid

        if isinstance(self.gid, bool):
            gid = pwd.getpwnam(environ['wsgidav.auth.user_name']).pw_gid
        else:
            gid = self.gid

        return uid, gid

    def get_resource_inst(self, path, environ):
        """Return info dictionary for path.

        See DAVProvider.get_resource_inst()
        """
        self._count_get_resource_inst += 1
        fp = self._loc_to_file_path(path, environ)
        if not os.path.exists(fp):
            return None

        uid, gid = self.get_user_group(environ)

        if os.path.isdir(fp):
            return AuthedFolderResource(path, environ, fp, uid, gid, self.chmask)
        return fdp.FileResource(path, environ, fp)


# noinspection PyAbstractClass
class AuthedFolderResource(fdp.FolderResource):
    def __init__(self, path, environ, fp, uid, gid, chmask):
        super().__init__(path, environ, fp)
        self.uid = uid
        self.gid = gid
        self.chmask = chmask

    def create_empty_resource(self, name):
        """Create an empty (length-0) resource.

        See DAVResource.create_empty_resource()
        """
        assert "/" not in name
        if self.provider.readonly:
            raise fdp.DAVError(fdp.HTTP_FORBIDDEN)
        path = util.join_uri(self.path, name)
        # noinspection PyProtectedMember
        fp = self.provider._loc_to_file_path(path, self.environ)
        f = open(fp, "wb")
        f.close()
        os.chown(fp, self.uid, self.gid)
        os.chmod(fp, self.chmask)
        return self.provider.get_resource_inst(path, self.environ)
