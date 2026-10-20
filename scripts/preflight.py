"""Non-invasive serving preflight; never probes or prints configured endpoint values."""

import os
import platform
import sys


def main() -> None:
    print(f"platform={platform.system()}-{platform.release()}")
    print(f"python={sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    print(f"generation_endpoint_configured={'yes' if os.environ.get('NASI_LEMAK_GENERATION_URL') else 'no'}")
    print("network_probe=not_performed")
    print("model_load=not_performed")
    print("status=preflight_only_real_serving_blocked")


if __name__ == "__main__":
    main()
