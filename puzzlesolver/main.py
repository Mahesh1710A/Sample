import logging
from telegram import __version__ as TG_VER
from keep_alive import keep_alive

try:
  from telegram import __version_info__
except ImportError:
  __version_info__ = (0, 0, 0, 0, 0)  # type: ignore[assignment]

if __version_info__ < (20, 0, 0, "alpha", 1):
  raise RuntimeError(
      f"This example is not compatible with your current PTB version {TG_VER}. To view the "
      f"{TG_VER} version of this example, "
      f"visit https://docs.python-telegram-bot.org/en/v{TG_VER}/examples.html")

from telegram import ForceReply, Update
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters
import hashlib
import codecs
import ecdsa
import base58
from functools import lru_cache
import os

my_bot_token = os.environ['BOT_TOKEN']
keep_alive()

# Enable logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO)
# set higher logging level for httpx to avoid all GET and POST requests being logged
logging.getLogger("httpx").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

start_range = None
end_range = None
target_address = None


@lru_cache
def to_64_digit_hex(number):
  hex_number = hex(number)[2:]
  padded_hex = hex_number.zfill(64)
  return padded_hex


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
  user = update.effective_user
  await update.message.reply_html(
      rf"Hi {user.mention_html()}!",
      reply_markup=ForceReply(selective=True),
  )


async def start_range_command(update: Update,
                              context: ContextTypes.DEFAULT_TYPE) -> None:
  global start_range
  try:
    start_range = int(update.message.text.split()[1])
    await update.message.reply_text(f"Start range set to: {start_range}")
  except (IndexError, ValueError):
    await update.message.reply_text(
        "Please provide a valid integer for the start range.")


async def end_range_command(update: Update,
                            context: ContextTypes.DEFAULT_TYPE) -> None:
  global end_range
  try:
    end_range = int(update.message.text.split()[1])
    await update.message.reply_text(f"End range set to: {end_range}")
  except (IndexError, ValueError):
    await update.message.reply_text(
        "Please provide a valid integer for the end range.")


async def address_command(update: Update,
                          context: ContextTypes.DEFAULT_TYPE) -> None:
  global target_address
  target_address = update.message.text.split()[1]
  await update.message.reply_text(f"Target address set to: {target_address}")


async def current_command(update: Update,
                          context: ContextTypes.DEFAULT_TYPE) -> None:
  if start_range is not None and end_range is not None:
    await update.message.reply_text(
        f"Current range: {start_range} to {end_range}")
  else:
    await update.message.reply_text(
        "Range not yet set. Please use /start_range and /end_range commands.")


async def generate_and_check(update: Update,
                             context: ContextTypes.DEFAULT_TYPE) -> None:
  global start_range, end_range, target_address
  if start_range is None or end_range is None or target_address is None:
    await update.message.reply_text(
        "Please set the range and target address first using /start_range, /end_range, and /address commands."
    )
    return

  await update.message.reply_text("Searching...")  # Add this line

  for number in range(start_range, end_range):
    hex_64_digit = to_64_digit_hex(number)
    private_key = str(hex_64_digit)

    private_key_bytes = codecs.decode(private_key, 'hex')
    public_key_raw = ecdsa.SigningKey.from_string(
        private_key_bytes, curve=ecdsa.SECP256k1).verifying_key
    public_key_bytes = public_key_raw.to_string()
    public_key_hex = codecs.encode(public_key_bytes, 'hex')
    public_key = (b'04' + public_key_hex).decode("utf-8")

    if (ord(bytearray.fromhex(public_key[-2:])) % 2 == 0):
      public_key_compressed = '02'
    else:
      public_key_compressed = '03'

    public_key_compressed += public_key[2:66]

    hex_str = bytearray.fromhex(public_key_compressed)
    sha = hashlib.sha256()
    sha.update(hex_str)
    sha.hexdigest()

    rip = hashlib.new('ripemd160')
    rip.update(sha.digest())
    key_hash = rip.hexdigest()

    modified_key_hash = "00" + key_hash

    sha = hashlib.sha256()
    hex_str = bytearray.fromhex(modified_key_hash)
    sha.update(hex_str)
    sha.hexdigest()

    sha_2 = hashlib.sha256()
    sha_2.update(sha.digest())
    sha_2.hexdigest()

    checksum = sha_2.hexdigest()[:8]

    byte_25_address = modified_key_hash + checksum
    address = base58.b58encode(bytes(
        bytearray.fromhex(byte_25_address))).decode('utf-8')
    if address == target_address:
      await update.message.reply_text(
          f"Found Address: {address}, Private Key: {private_key}")
      return
  await update.message.reply_text("Address not found within the range.")


def main() -> None:
  application = Application.builder().token(my_bot_token).build()

  application.add_handler(CommandHandler("start", start))
  application.add_handler(CommandHandler("start_range", start_range_command))
  application.add_handler(CommandHandler("end_range", end_range_command))
  application.add_handler(CommandHandler("address", address_command))
  application.add_handler(CommandHandler("current", current_command))
  application.add_handler(CommandHandler("generate", generate_and_check))

  application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
  main()
