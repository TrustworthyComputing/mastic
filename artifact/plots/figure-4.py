import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from matplotlib import rc

rc('font',**{'family':'serif','serif':['Palatino']})
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
    # Set the font to be serif, rather than sans
    sns.set(font='serif', rc=paper_rc)
    sns.set_style('whitegrid', rc=paper_rc)

    palette = sns.color_palette('deep')
    sns.set_palette(palette)

set_style()

df = pd.DataFrame(pd.read_csv('data/figure-4.csv'))
bits = 256
df_bits = df[df['bits'] == bits]

fig = plt.figure(figsize=(6, 1.5))
ax = sns.lineplot(x='Number of clients ($N$)', y='Runtime (sec.)', hue='protocol',
                    style='protocol', markers=True, data=df_bits, err_style="bars", alpha=None,dashes=False,
                    err_kws={
                        'elinewidth':1, 'capsize':5, 'capthick':1, # 'alpha':0.2
                        }
                    )
# plt.setp(ax.err_lines, alpha=.3)

ax.legend(ncol=2, loc='upper left')
ax.xaxis.grid(False)  # remove vertical axis
ax.set_yscale('log')
ax.grid(True, which="minor", axis='y', ls="dotted")

ax.set_ylim([25, 10000])
fig.savefig('./pdfs/figure-4.pdf', format='pdf', bbox_inches='tight')
