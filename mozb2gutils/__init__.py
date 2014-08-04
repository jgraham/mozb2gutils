import ConfigParser
import os
import re
import threading
import time
import traceback

from mozdevice import adb
from mozlog.structured import get_default_logger

here = os.path.split(__file__)[0]

class WaitTimeout(Exception):
    pass

logger = None
def setup_logging():
    global logger
    logger = get_default_logger("mozb2gutils")
    if logger is None:
        import logging
        logger = logging.getLogger()

def get_device(device):
    if device is None:
        return devices()[0]
    return device


class WaitThread(threading.Thread):
    daemon = True
    def __init__(self, func, args=None, kwargs=None):
        self.func = func
        self.initalized = threading.Event()

        self.args = args if args is not None else ()
        self.kwargs = kwargs if kwargs is not None else {}
        self.kwargs["poll_func"] = self._poll
        threading.Thread.__init__(self)

    def _poll(self, *args, **kwargs):
        self.initalized.set()
        return poll_wait(*args, **kwargs)

    def run(self):
        self.func(*self.args, **self.kwargs)


class DeviceBackup(object):
    def __init__(self):
        self.device = adb.ADBDevice()
        self.backup_dirs = ["/data/local",
                            "/data/b2g/mozilla"]
        self.backup_files = ["/system/etc/hosts"]

    def local_dir(self, remote):
        return os.path.join(self.backup_path, remote.lstrip("/"))

    def __enter__(self):
        self.backup_path = tempfile.mkdtemp()

        for remote_path in self.backup_dirs:
            local_path = self.local_dir(remote_path)
            if not os.path.exists(local_path):
                os.makedirs(local_path)
            self.device.pull(remote_path, local_path)

        for remote_path in self.backup_files:
            remote_dir, filename = remote_path.rsplit("/", 1)
            local_dir = self.local_dir(remote_dir)
            local_path = os.path.join(local_dir, filename)
            if not os.path.exists(local_dir):
                os.makedirs(local_dir)
            self.device.pull(remote_path, local_path)

        return self

    def __exit__(self, *args, **kwargs):
        shutil.rmtree(self.backup_path)

    def restore(self):
        self.device.remount()

        for remote_path in self.backup_files:
            remote_dir, filename = remote_path.rsplit("/", 1)
            local_path = os.path.join(self.local_dir(remote_dir), filename)
            self.device.rm(remote_path)
            self.device.push(local_path, remote_path)

        for remote_path in self.backup_dirs:
            local_path = self.local_dir(remote_path)
            self.device.rmdir(remote_path)
            self.device.push(local_path, remote_path)


class PushFile(object):
    """Context manager that installs a file onto the device, and removes it again"""
    def __init__(self, device, local, remote):
        self.device = device
        self.local = local
        self.remote = remote

    def __enter__(self, *args, **kwargs):
        if self.remote.startswith("/system/"):
            self.device.remount()
        self.device.push(self.local, self.remote)

    def __exit__(self, *args, **kwargs):
        self.device.rm(self.remote)


def poll_wait(func, interval=1.0, timeout=30):
    start_time = time.time()
    while time.time() - start_time < timeout:
        print "Polling", time.time() - start_time
        value = func()
        if value:
            return value
        time.sleep(interval)

    raise WaitTimeout()

_ip_regexp = re.compile(r'UP\s+([1-9]\d{0,2}\.\d{1,3}\.\d{1,3}\.\d{1,3})')


class B2GUtils(object):
    def __init__(self, device_serial=None):
        self.device = adb.ADBDevice(device_serial)

    def wait_for_device_ready(self, timeout=30, poll_func=poll_wait):
        logger.info("Waiting for device to become ready")
        profiles = self.profiles()
        assert len(profiles) == 1

        profile_dir = profiles.itervalues().next()
        prefs_file = os.path.normpath(profile_dir + "/prefs.js")

        def prefs_modified():
            mtime = [None, None]

            def inner():
                try:
                    mtime[1] = self.device.shell_output("stat %s" % (prefs_file))
                except:
                    print traceback.format_exc()
                    return False

                print mtime

                if mtime[0] is not None and mtime[1] != mtime[0]:
                    return True

                mtime[0] = mtime[1]
                return False

            return inner

        with PushFile(self.device, os.path.join(here, "stat"), "/system/bin/stat"):
            poll_func(prefs_modified(), timeout=timeout)

    def ip_address(self):
        data = self.device.shell_output('netcfg')
        lines = data.split("\n")
        for line in lines[1:]:
            match = _ip_regexp.search(line)
            if match:
                return match.groups()[0]
        return None

    def wait_for_net(self, timeout=30, poll_func=poll_wait):
        """Wait for the device to be assigned an IP address"""
        logger.info("Waiting for network connection")
        poll_func(self.ip_address, timeout=timeout)


    def restart_b2g(self, timeout=30):
        self.device.shell_bool("stop b2g")
        wait_thread = WaitThread(self.wait_for_device_ready)
        wait_thread.start()
        self.device.shell_bool("start b2g")
        wait_thread.join(timeout=timeout)

    def reboot(self, timeout=60):
        wait_thread = WaitThread(self.wait_for_device_ready)
        wait_thread.start()
        wait_thread.initalized.wait(timeout=30)
        self.device.command_bool(["reboot"])
        wait_thread.join(timeout=timeout)


    def profiles(self):
        profile_base = "/data/b2g/mozilla"

        rv = {}

        with self.device.shell("cat %s/profiles.ini" % profile_base) as proc:
            config = ConfigParser.ConfigParser()
            config.readfp(proc.stdout_file)
            for section in config.sections():
                items = dict(config.items(section))
                if "name" in items and "path" in items:
                    path = items["path"]
                    if "isrelative" in items and int(items["isrelative"]):
                        path = os.path.normpath("%s/%s"% (profile_base, path))
                    rv[items["name"]] = path

        return rv
