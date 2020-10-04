import stratum
import comunications
import logging
logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)


stratum.start()
comunications.start()