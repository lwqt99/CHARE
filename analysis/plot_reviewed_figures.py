"""Redraw the CHARE paper figures and account for repeated plan bytes."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path

from plot_paper_study import collect, summarize, write_csv


WIDTH_MM = 177.95
HEIGHT_MM = 60
CAPACITIES = (4, 8, 16)
STYLES = (
    ('#0072B2', 'o', '-', 'evalblue,mark=*,solid'),
    ('#404040', 's', '--', 'black!75,mark=square*,dashed'),
    ('#666666', '^', ':', 'black!60,mark=triangle,dotted'),
)
# A panel contains a heading, a quantity with units, a scale and explicit series.
PANELS = {
    'lifecycle': (
        ('Initialization', 'Time (s)', 'log',
         [('initialization', 'CHARE', 'CHARE', 0), ('initialization', 'DH-explicit-list', 'DH (authorized list)', 1)]),
        ('Withdrawals and acquisitions', 'Time (s)', 'log',
         [('updates_and_acquisitions', 'CHARE', 'CHARE', 0), ('updates_and_acquisitions', 'DH-explicit-list', 'DH (authorized list)', 1)]),
    ),
    'helper': (
        ('Directory', 'Update time (ms)', 'log',
         [('directory_update', 'delta', 'Cached update', 0), ('directory_update', 'rebuild', 'Rebuild', 1)]),
        ('Receiver', 'Update time (ms)', 'log',
         [('client_helper_update', 'delta', 'Cached update', 0), ('client_helper_update', 'rebuild', 'Rebuild', 1)]),
    ),
    'transport': (
        ('Initial delivery', 'Serialized size (MiB)', 'log',
         [('transport_A_first', 'full', 'Full ciphertext', 1), ('entry_fanout_A_first', 'reference', 'All client entry installs', 2)]),
        ('Repeat delivery', 'Serialized size (MiB)', 'log',
         [('transport_A_fresh_repeat', 'full', 'Full ciphertext', 1), ('transport_A_fresh_repeat', 'reference', 'Repeat packet', 0)]),
    ),
    'service': (
        ('Service execution', 'Time (s)', 'linear',
         [('service_execution', 'tree', 'Tree', 0), ('service_execution', 'cycle', 'Cycle', 1)]),
        ('Serialized messages', 'Size (MiB)', 'linear',
         [('service_serialized_messages', 'tree', 'Tree', 0), ('service_serialized_messages', 'cycle', 'Cycle', 1)]),
    ),
}


def series_data(summary):
    index = {(r['metric'], r['series'], r['capacity']): r for r in summary}
    result = {}
    points = []
    for name, panels in PANELS.items():
        result[name] = []
        for i, (title, axis, scale, series) in enumerate(panels):
            traces = []
            for metric, key, label, style in series:
                multiplier = 0.001 if metric == 'service_execution' else 1
                rows = []
                for n in CAPACITIES:
                    source = index[metric, key, n]
                    row = {field: source[field]*multiplier for field in ('minimum', 'median', 'maximum')}
                    assert source['samples'] == 3
                    assert row['minimum'] <= row['median'] <= row['maximum']
                    assert scale != 'log' or row['minimum'] > 0
                    rows.append(row)
                    points.append(dict(figure=name, panel='ab'[i], metric=metric, series=key,
                                       capacity=n, unit='s' if multiplier != 1 else source['unit'], **row))
                traces.append((label, style, rows))
            result[name].append((f'({"ab"[i]}) {title}', axis, scale, traces))
    return result, points


def common_limits(name, panels):
    if name == 'service':
        return None
    values = [row for _, _, _, traces in panels for _, _, rows in traces for row in rows]
    return min(row['minimum'] for row in values)/1.7, max(row['maximum'] for row in values)*1.65


def draw(name, panels, out):
    import matplotlib
    matplotlib.use('Agg')
    from matplotlib import pyplot as plt
    from matplotlib import ticker
    from matplotlib.font_manager import FontProperties, findfont

    family = FontProperties(family=['Times New Roman', 'Liberation Serif', 'DejaVu Serif'])
    font = FontProperties(fname=findfont(family, fallback_to_default=False)).get_name()
    plt.rcParams.update({'font.family': font, 'font.size': 9,
                         'mathtext.fontset': 'stix', 'pdf.fonttype': 42, 'svg.fonttype': 'none',
                         'axes.labelsize': 9, 'xtick.labelsize': 8.2, 'ytick.labelsize': 8.2})
    figure, axes = plt.subplots(1, 2, figsize=(WIDTH_MM/25.4, HEIGHT_MM/25.4))
    figure.subplots_adjust(left=.095, right=.985, bottom=.25, top=.80, wspace=.38)
    limits = common_limits(name, panels)
    shared = panels[0][3][0][0] == panels[1][3][0][0] and name != 'transport'
    for i, (ax, (title, quantity, scale, traces)) in enumerate(zip(axes, panels)):
        for label, style, rows in traces:
            color, marker, linestyle, _ = STYLES[style]
            ax.errorbar(CAPACITIES, [r['median'] for r in rows],
                        yerr=[[r['median']-r['minimum'] for r in rows],
                              [r['maximum']-r['median'] for r in rows]],
                        label=label, color=color, marker=marker, linestyle=linestyle,
                        markerfacecolor='white' if style == 2 else color,
                        linewidth=1.1, markersize=4.5, capsize=2.5)
        ax.set(xlim=(3.2, 16.8), xticks=CAPACITIES, xlabel='Capacity $N$\n'+title, ylabel=quantity)
        ax.set_yscale(scale)
        if limits:
            ax.set_ylim(*limits)
            ax.yaxis.set_minor_locator(ticker.NullLocator())
        else:
            ax.set_ylim(bottom=0)
        ax.grid(axis='y', color='.88', linewidth=.55)
        ax.spines[['top', 'right']].set_visible(False)
        if not shared:
            ax.legend(loc='lower center', bbox_to_anchor=(.5, 1.025), ncol=2,
                      frameon=False, fontsize=8, columnspacing=.85, handlelength=1.6)
    if shared:
        handles, labels = axes[0].get_legend_handles_labels()
        figure.legend(handles, labels, loc='upper center', bbox_to_anchor=(.53, .965),
                      ncol=2, frameon=False, fontsize=8.5)
    for extension in ('pdf', 'svg', 'png'):
        figure.savefig(out/f'{name}.{extension}', dpi=300)
    plt.close(figure)
    return font


def write_inline(name, panels, out):
    """Generate self-contained vector drawings using the paper's document fonts."""
    limits = common_limits(name, panels)
    shared = name != 'transport'
    lines = [
        '% Generated by plot_reviewed_figures.py from the audited native batch.',
        r'\begingroup', r'\definecolor{evalblue}{HTML}{0072B2}', r'\begin{tikzpicture}',
        r'\begin{groupplot}[group style={group size=2 by 1,horizontal sep=1.15cm},',
        r'width=7.83cm,height=4.85cm,axis lines=left,xmin=3.2,xmax=16.8,xtick={4,8,16},',
        r'tick label style={font=\small},label style={font=\small},',
        r'legend style={draw=none,fill=none,font=\small,legend columns=-1,',
        r'at={(0.5,1.035)},anchor=south,column sep=3pt},',
        r'ymajorgrids,grid style={black!13},scaled y ticks=false]',
    ]
    for i, (title, axis, scale, traces) in enumerate(panels):
        options = r'xlabel={\shortstack{Capacity $N$\\'+title+r'}},ylabel={'+axis+'}'
        options += ',ymode=log,minor y tick num=0' if scale == 'log' else ',ymin=0'
        if limits:
            options += f',ymin={limits[0]:.12g},ymax={limits[1]:.12g}'
        lines.append(r'\nextgroupplot['+options+']')
        for label, style, rows in traces:
            lines.append(r'\addplot['+STYLES[style][3]+r',mark size=1.9pt,line width=0.75pt,error bars/.cd,y dir=both,y explicit] coordinates {')
            for n, r in zip(CAPACITIES, rows):
                lines.append(f"({n},{r['median']:.12g}) += (0,{r['maximum']-r['median']:.12g}) -= (0,{r['median']-r['minimum']:.12g})")
            lines.append('};')
            if not shared or i == 0:
                lines.append(r'\addlegendentry{'+label+'}')
    lines.append(r'\end{groupplot}')
    lines += [r'\end{tikzpicture}', r'\endgroup']
    (out/f'figure_{name}.tex').write_text('\n'.join(lines)+'\n', encoding='utf-8')


def service_bytes(run, observations):
    """Account for the one complete plan field in every measured sent object."""
    modes = {'pad_sample_deliver_install': 'all_directions', 'plan_readiness': 'all_holders',
             'contribute_and_authenticate': 'all_directions', 'plan_bytes': 'complete_bound_plan'}
    with (run/'raw.csv').open(encoding='utf-8-sig', newline='') as stream:
        rows = [r for r in csv.DictReader(stream)
                if r['scheme'] in ('CHARE-service-tree', 'CHARE-service-cycle')
                and modes.get(r['operation']) == r['mode']]
    audit = {(r['case_id'], r['series']): r['value'] for r in observations
             if r['metric'] == 'service_serialized_messages'}
    assert len(rows) == 4*len(audit)
    result = []
    for case, graph in sorted(audit):
        entries = {r['operation']: r for r in rows
                   if (r['case_id'], r['scheme']) == (case, 'CHARE-service-'+graph)}
        assert set(entries) == set(modes)
        plan = entries.pop('plan_bytes')
        n = int(plan['capacity'])
        assert [int(entries[key]['count']) for key in list(modes)[:-1]] == [
            2*(n-1 if graph == 'tree' else n), n, 2*n]
        total = sum(int(r['bytes']) for r in entries.values())
        copies = sum(int(r['count']) for r in entries.values())
        assert total/2**20 == audit[case, graph]
        plan_bytes = int(plan['bytes'])*copies
        assert 0 < plan_bytes < total
        result.append(dict(case_id=case, capacity=n, graph=graph, plan_size_bytes=int(plan['bytes']),
                           plan_copies=copies, serialized_bytes=total, repeated_plan_bytes=plan_bytes,
                           other_serialized_bytes=total-plan_bytes))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run', type=Path, help='Validated native result directory')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output
    out.mkdir(parents=True, exist_ok=False)
    records, _, _, manifest, _ = collect(args.run)
    summary = summarize(records)
    figures, points = series_data(summary)
    fonts = set()
    for name, panels in figures.items():
        fonts.add(draw(name, panels, out))
        write_inline(name, panels, out)
    write_csv(out/'plotted_values.csv', points)
    write_csv(out/'service_bytes.csv', service_bytes(args.run, records))
    write_csv(out/'native_summary.csv', summary)
    hashes = {name: hashlib.sha256((args.run/name).read_bytes()).hexdigest()
              for name in ('raw.csv', 'checks.csv', 'parameters.txt', 'source_manifest.json')}
    (out/'figure_provenance.json').write_text(json.dumps(
        {'raw_files': hashes, 'figure_points': len(points), 'cases': len({r['case_id'] for r in records}),
         'implementation': manifest['implementation_version'], 'width_mm': WIDTH_MM, 'height_mm': HEIGHT_MM,
         'standalone_fonts': sorted(fonts),
         'interval': 'Observed minimum and maximum around the median of three trials',
         'byte_decomposition': 'Native sent object lengths minus one plan field per recorded object',
         'figures': list(figures)}, indent=2)+'\n', encoding='utf-8')


if __name__ == '__main__':
    main()
