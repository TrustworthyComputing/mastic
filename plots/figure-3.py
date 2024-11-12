import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from matplotlib import rc

rc('font', **{'family': 'serif', 'serif': ['Palatino']})
plt.rcParams['pdf.fonttype'] = 42

def set_style():
    paper_rc = {
        'font.family': 'serif',
        'font.serif': ['Times', 'Palatino', 'serif'],
        'font.size': 12,
        'legend.fontsize': 10,
        'lines.linewidth': 2,
        'lines.markersize': 7,
        'grid.linestyle': '--',
        'ytick.major.size': 0.1,
        'ytick.minor.size': 0.05,
    }
    sns.set(font='serif', rc=paper_rc)
    sns.set_style('whitegrid', rc=paper_rc)

    palette = sns.color_palette('colorblind')
    palette[1], palette[2] = palette[2], palette[1]
    sns.set_palette(palette)

set_style()

df = pd.DataFrame(pd.read_csv('data/figure-3.csv'))

hatches = ['////', '\\\\\\', '|||', '---', '+++']

# Create a subplot with 1 row and 2 columns
fig, axs = plt.subplots(1, 2, sharex=True, figsize=(6, 1))
plt.subplots_adjust(wspace=0.32)

# Runtime
width = 0.9
ax1 = sns.barplot(ax=axs[0], data=df, x='Number of Bits ($n$)', y='Runtime (ms)', hue='Protocol', linewidth=1, edgecolor='black', alpha=0.7, width=width, gap=0.2)
ax1.get_legend().remove()
# ax1.set(title="Report Generation Time")
ax1.xaxis.grid(False)
ax1.set_yscale('log')
ax1.grid(True, which="minor", axis='y', ls="dotted")
ax1.set_ylim([0.01, 0.5])

# Communication
ax2 = sns.barplot(ax=axs[1], data=df, x='Number of Bits ($n$)', y='Size (KB)', hue='Protocol', linewidth=1, edgecolor='black', alpha=0.7, width=width, gap=0.2)
# ax2.set(title="Report Size")
ax2.get_legend().remove()
ax2.xaxis.grid(False)
ax2.set_yscale('log')
ax2.grid(True, which="minor", axis='y', ls="dotted")
ax2.set_ylim([4, 250])

for i, bar in enumerate(ax1.patches):
    bar.set_hatch(hatches[(i // 3) % 5])
    bar._hatch_color = (0.9, 0.9, 0.9)
for i, bar in enumerate(ax2.patches):
    bar.set_hatch(hatches[(i // 3) % 5])
    bar._hatch_color = (0.9, 0.9, 0.9)

handles, labels = ax1.get_legend_handles_labels()
for i in range(len(handles)):
    handles[i].set_hatch(hatches[i])
fig.legend(handles, labels, bbox_to_anchor=(0.47, 1.43), loc='upper center', ncol=3)

# Save the combined figure
fig.savefig('./pdfs/figure-3.pdf', format='pdf', bbox_inches='tight')
