from wsgidav.dc.pam_dc import PAMDomainController
from wsgidav.dav_error import DAVError
from wsgidav.util import get_module_logger
from redis import Redis
from time import time, sleep
from datetime import timedelta
from threading import Thread


_logger = get_module_logger(__name__)


# noinspection PyAbstractClass
class PAMLockoutController(PAMDomainController):
    """
    An extension of the PAM domain controller that implements a timed lockout method
    """
    @staticmethod
    def get_real_remote_addr(environ: dict) -> str:
        env = {
            k.lower().replace('-', '_').replace(' ', '_'): v for k, v in environ.items()
            if isinstance(v, str)
            and (('.' in v) or (':' in v))
        }
        if 'http_x_forwarded_for' in env:
            return env['http_x_forwarded_for'].split(',')[0].strip()

        if 'http_remote_addr' in env:
            return env['http_remote_addr'].strip()

        return env.get('remote_addr', '').strip()

    def __init__(self, wsgidav_app, config):
        super().__init__(wsgidav_app, config)

        lockout_conf = config.get('pam_dc', {}).get('lockout', {})
        self.redis = Redis(
            host=lockout_conf.get('redis_host', 'localhost'),
            port=int(lockout_conf.get('redis_port', 6379)),
            db=int(lockout_conf.get('redis_db', 0)),
            password=lockout_conf.get('redis_password', None)
        )
        self.prefix = lockout_conf.get('redis_prefix', 'wsgidav_login_attempt_')

        self.daemon = Thread(
            target=self._setter_thread,
            args=(lockout_conf.get('timing', 3),),
            daemon=True
        )
        self.daemon.start()
        self.todo = {}

    def basic_auth_user(self, realm, user_name, password, environ):
        remote_addr = self.get_real_remote_addr(environ)
        redis_key = self.prefix + remote_addr
        r_data = self.redis.get(redis_key)
        attempts, next_allowed = tuple(int(i) for i in (r_data or b'0:0').split(b':'))
        now = time()

        if attempts:
            if now < next_allowed:
                _logger.warning("remote host '{}' denied login: too many attempts".format(remote_addr))
                raise DAVError(429)

        if super().basic_auth_user(realm, user_name, password, environ):
            self.todo[redis_key] = 'DROP'
            return True

        self.todo[redis_key] = attempts
        return False

    def _setter_thread(self, timing: (str, int, float, list)):
        """Setting redis values in async speeds up response times"""
        if isinstance(timing, (str, int)):
            timing = float(timing)
        exponential = isinstance(timing, float)
        while True:
            sleep(0.1)
            for key in list(self.todo.keys()):
                value = self.todo.pop(key)
                if value == 'DROP':
                    self.redis.delete(key)
                else:
                    if exponential:
                        timeout = timing ** value
                        r_time = timedelta(seconds=(timeout * timeout) + 1600)
                        next_allowed = time() + timeout
                    else:
                        r_time = timedelta(minutes=timing[1])
                        next_allowed = 0 if (value < timing[0]) else (time() + (timing[1] * 60))

                    self.redis.setex(name=key, time=r_time, value=b'%d:%d' % (value + 1, int(next_allowed)))
