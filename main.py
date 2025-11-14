import asyncio
import signal
import logging
from os import environ as env
from pathlib import Path

_HAS_UVLOOP = False
try:
    import uvloop
    _HAS_UVLOOP = True
except ImportError:
    pass


from notarized_notes_dvm import NotarizedNotesDVM

from dotenv import load_dotenv

def set_up_logger(log_level: str):
    log_level = log_level.upper()
    assert log_level in ('INFO', 'DEBUG', 'WARN', 'ERROR'), f"invalid log level: {log_level}"
    logging.basicConfig(
        level=getattr(logging, log_level),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

async def main():
    load_dotenv()
    relays: list[str] = [r.strip() for r in env['NOSTR_RELAYS'].split(',')]
    private_key: str = env['PRIVATE_KEY_HEX'].strip()
    db_path: Path = Path(env['DB_PATH'])
    electrum_server: str = env['ELECTRUM_SERVER']

    log_level: str = env.get('LOG_LEVEL', 'INFO')
    set_up_logger(log_level)
    logger = logging.getLogger('dvm-application')
    logger.info(
        f"ENV:\n{relays=}\n{db_path=}\n{electrum_server=}\n{log_level=}"
    )

    shutdown_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    loop.add_signal_handler(signal.SIGINT, shutdown_event.set)  # type: ignore
    loop.add_signal_handler(signal.SIGTERM, shutdown_event.set)  # type: ignore
    async with NotarizedNotesDVM(relays, private_key, db_path, electrum_server) as _dvm:
        logger.info(f"Notarized Notes DVM running")
        await shutdown_event.wait()
    await asyncio.sleep(0.25)
    logger.info(f"Notarized Notes DVM stopped")

if __name__ == "__main__":
    if _HAS_UVLOOP:
        uvloop.run(main())
    else:
        asyncio.run(main())