import matplotlib.pyplot as plt

data = {
    "m1": {"detected_scans": 72, "not_detected_scans": 40},
    "m2": {"detected_scans": 62, "not_detected_scans": 50},
    "m3": {"detected_scans": 59, "not_detected_scans": 53},
    "m4": {"detected_scans": 95, "not_detected_scans": 17},
    "m5": {"detected_scans": 66, "not_detected_scans": 46},
    "ours": {"detected_scans": 107, "not_detected_scans": 5},
}

labels = list(data.keys())
detected_scans = [entry["detected_scans"] for entry in data.values()]
not_detected_scans = [entry["not_detected_scans"] for entry in data.values()]

bar_width = 0.35
index = range(len(labels))

fig, ax = plt.subplots(figsize=(12, 5))  # Adjust the figsize here

bar1 = ax.bar(index, detected_scans, bar_width, label='Detected Scans', color="#ff0036", alpha=0.7)
bar2 = ax.bar([i + bar_width for i in index], not_detected_scans, bar_width, label='Not Detected Scans', color="#457fe6", alpha=0.7)

ax.set_xlabel('Method', fontsize=16)  # Set the font size for xlabel
ax.set_ylabel('Number of Scans', fontsize=16)  # Set the font size for ylabel

# Display counts on bar1
for i, detected in enumerate(detected_scans):
    ax.text(i, detected, f"{detected}", ha='center', va='bottom', fontsize=14)  # Set the font size for text

# Display counts on bar2
for i, (detected, not_detected) in enumerate(zip(detected_scans, not_detected_scans)):
    ax.text(i + bar_width, not_detected, f"{not_detected}", ha='center', va='bottom', fontsize=14)  # Set the font size for text

ax.set_xticks([i + bar_width / 2 for i in index])
ax.set_xticklabels(labels, fontsize=14)  # Set the font size for xtick labels

ax.tick_params(axis='y', labelsize=14)  # Set the font size for y-axis ticks

ax.legend(fontsize=16)  # Set the font size for legend

plt.show()
