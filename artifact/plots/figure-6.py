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
fig = plt.figure(figsize=(6, 1.5))

df = pd.DataFrame(pd.read_csv('data/figure-6.csv'))
df_bits = df[df['m'] == 100]
# df_bits = df[(df['Attributes'] == 1) & (df['m'] == 100)]

### Extrapolated ###
d = df_bits.copy()
d.loc[(d['Number of clients ($N$)'] == '10$^5$') & (d['protocol'] == 'Prio $A$ = 1024'), 'Runtime (sec.)'] = 3000
d.loc[(d['Number of clients ($N$)'] == '10$^6$') & (d['protocol'] == 'Prio $A$ = 128'), 'Runtime (sec.)'] = 25000
d.loc[(d['Number of clients ($N$)'] == '10$^6$') & (d['protocol'] == 'Prio $A$ = 1024'), 'Runtime (sec.)'] = 80000
ax = sns.lineplot(x='Number of clients ($N$)', y='Runtime (sec.)', hue='protocol',
                    style='protocol', markers=True, data=d, err_style="bars", alpha=0.25, err_kws={'elinewidth':1, 'capsize':5, 'capthick':1}, legend=False)
### Extrapolated ###

ax = sns.lineplot(x='Number of clients ($N$)', y='Runtime (sec.)', hue='protocol', dashes=False,
                    style='protocol', markers=True, data=df_bits, err_style="bars", alpha=None, err_kws={'elinewidth':1, 'capsize':5, 'capthick':1})

# ax.legend(ncol=1, loc='upper left')
ax.legend(ncol=3, loc='upper left', bbox_to_anchor=(0, 1.46))
ax.xaxis.grid(False)  # remove vertical axis
ax.set_yscale('log')
ax.set_ylim([0.2, 5000])
ax.axes.set_yticks([1,10,100,1000,10000])
ax.axes.set_yticklabels(['$\\mathdefault{10^{0}}$',
                          '$\\mathdefault{10^{1}}$','$\\mathdefault{10^{2}}$',
                          '$\\mathdefault{10^{3}}$','$\\mathdefault{10^{4}}$'])
ax.grid(True, which="minor", axis='y', ls="dotted")
# ax.set_ylim([0.25, 50000])

fig.savefig('./pdfs/attributes.pdf', format='pdf', bbox_inches='tight')
