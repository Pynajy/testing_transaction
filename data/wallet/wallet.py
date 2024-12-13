from sqlalchemy import create_engine, Column, String, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

import random
import string

Base = declarative_base()

class Wallet:
    def generate_testnet_wallet(self):
        wallet = "testnet-" + ''.join(random.choices(string.ascii_letters + string.digits, k=32))
        return wallet
