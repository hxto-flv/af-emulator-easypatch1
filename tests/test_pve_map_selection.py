from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class PVEMapSelectionTests(unittest.TestCase):
    def text(self, rel):
        return (ROOT / rel).read_text(encoding="utf-8", errors="replace")

    def test_client_map_is_enabled_by_default(self):
        server = self.text("server/assaultfire_server_v143b.py")
        self.assertIn('AF_DS_USE_CLIENT_MAP", "1"', server)
        self.assertIn('client_map = str(create_req.get("map_string") or "").strip()', server)

    def test_a10a_seeds_full_ds_settings(self):
        server = self.text("server/assaultfire_server_v143b.py")
        for marker in (
            'map_name=map_name',
            'mode_id=int(create_req.get("mode_id", 0x00002001))',
            'map_id=int(create_req.get("map_id", 0x002F))',
            'sub_mode_id=int(create_req.get("sub_mode_id", 0x00001001))',
            'room_flags=int(create_req.get("flags", 0x00003008))',
        ):
            self.assertIn(marker, server)

    def test_a11e_updates_reserved_map_before_lazy_spawn(self):
        server = self.text("server/assaultfire_server_v143b.py")
        spawner = self.text("server/assaultfire_ds_spawner.py")
        self.assertIn('map_name=settings.get("map_string") or None', server)
        self.assertIn('map_name: Optional[str] = None', spawner)
        self.assertIn('allocation.map_name = desired_map', spawner)
        self.assertIn('"--map", allocation.map_name', spawner)


if __name__ == "__main__":
    unittest.main()
