import sqlite3
import numpy as np
import matplotlib.pyplot as plt
from collections import defaultdict

DB = "tangle.db"
VOLTAGE = 3.3
CURRENT = 0.07

def plot_cdf_cp_tld_epc():
	conn = sqlite3.connect(DB)
	c = conn.cursor()

	# assumes confirmation_time is stored
	c.execute("""
		SELECT confirm_time - timestamp
		FROM tx
		WHERE confirm_time IS NOT NULL
	""")
	latencies = [row[0] for row in c.fetchall()]

	latencies.sort()
	cdf = np.arange(1, len(latencies)+1) / len(latencies)

	plt.figure()
	plt.plot(latencies, cdf)
	plt.xlabel("Confirmation Latency (seconds)")
	plt.ylabel("CDF")
	plt.title("CDF of Confirmation Latency")
	plt.grid(True)
	plt.savefig("CDF of Confirmation Latency")
	plt.show()
#--------------------------------------------------


	# bucket transactions by second
	c.execute("""
		SELECT CAST(timestamp AS INTEGER), COUNT(*),
		       SUM(CASE WHEN confirm_time IS NOT NULL THEN 1 ELSE 0 END)
		FROM tx
		GROUP BY CAST(timestamp AS INTEGER)
	""")

	rows = c.fetchall()

	load = []
	prob = []

	for ts, total, confirmed in rows:
		if total > 0:
		    load.append(total)
		    prob.append(confirmed / total)

	plt.figure()
	plt.scatter(load, prob)
	plt.xlabel("Transaction Rate (tx/s)")
	plt.ylabel("Confirmation Probability")
	plt.title("Confirmation Probability vs Traffic Load")
	plt.grid(True)
	plt.savefig("Confirmation Probability vs Traffic Load")
	plt.show()
#--------------------------------------------------




	c.execute("""
		SELECT first_approval_time - timestamp
		FROM tx
		WHERE first_approval_time IS NOT NULL
	""")

	lifetimes = [row[0] for row in c.fetchall()]

	plt.figure()
	plt.hist(lifetimes, bins=20)
	plt.xlabel("Tip Lifetime (seconds)")
	plt.ylabel("Frequency")
	plt.title("Tip Lifetime Distribution")
	plt.grid(True)
	plt.savefig("Tip Lifetime Distribution")
	plt.show()
#--------------------------------------------------




	c.execute("""
		SELECT pow_time_ms
		FROM tx
		WHERE confirm_time IS NOT NULL
	""")

	pow_times = [row[0] for row in c.fetchall()]
	conn.close()

	energy = [VOLTAGE * CURRENT * (t / 1000) for t in pow_times]

	plt.figure()
	plt.plot(energy)
	plt.xlabel("Confirmed Transaction Index")
	plt.ylabel("Energy (Joule)")
	plt.title("Energy Consumption per Confirmed Transaction")
	plt.grid(True)
	plt.savefig("Energy Consumption per Confirmed Transaction")
	plt.show()






