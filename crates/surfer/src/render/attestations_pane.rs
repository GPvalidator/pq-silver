use std::iter;

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Paragraph, Row, Sparkline, Table},
};

use crate::{
    app::App,
    sources::attestations::{Arrivals, BIN_MS},
};

const BINS_PER_SEC: usize = (1_000 / BIN_MS) as usize;
const ARRIVAL_COLOR: Color = Color::Cyan;
const BARS: [char; 9] = [' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
/// Slot, total, late, first and peak, with their spacing.
const FIXED_COLUMNS: u16 = 10 + 9 + 7 + 8 + 15 + 5;

pub fn draw(f: &mut Frame, area: Rect, app: &mut App) {
    if app.attestations.all.total() == 0 {
        let block = Block::default().borders(Borders::ALL).title(" attestations ");
        let inner = block.inner(area);
        f.render_widget(block, area);
        f.render_widget(
            Paragraph::new("no pq attestation arrivals yet")
                .style(Style::default().fg(Color::DarkGray)),
            inner,
        );
        return;
    }
    // `None` is the row of every slot together.
    app.attestations_display_order = iter::once(None)
        .chain(app.attestations.slots().iter().rev().map(|held| Some(held.slot)))
        .collect();
    if !app.attestations_display_order.contains(&app.attestations_selected) {
        app.attestations_selected = None;
    }

    if app.drilled_in {
        draw_plot(f, area, app);
        return;
    }
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(app.split_pct),
            Constraint::Percentage(100 - app.split_pct),
        ])
        .split(area);
    draw_table(f, rows[0], app);
    draw_plot(f, rows[1], app);
}

/// Maps bins onto terminal columns: whole bins per column, or whole columns
/// per bin.
struct Scale {
    merge: usize,
    repeat: usize,
}

impl Scale {
    fn new(bins: usize, width: usize) -> Self {
        let bins = bins.max(1);
        Self { merge: bins.div_ceil(width.max(1)), repeat: (width / bins).max(1) }
    }

    fn columns(&self, bins: &[u32]) -> Vec<u64> {
        bins.chunks(self.merge)
            .flat_map(|chunk| {
                let sum = chunk.iter().map(|&count| u64::from(count)).sum();
                iter::repeat_n(sum, self.repeat)
            })
            .collect()
    }

    fn bin_of(&self, column: usize) -> usize {
        column / self.repeat * self.merge
    }
}

fn selected(app: &App, row: Option<u64>) -> &Arrivals {
    row.and_then(|slot| app.attestations.slot(slot)).unwrap_or(&app.attestations.all)
}

fn row_label(row: Option<u64>) -> String {
    row.map_or_else(|| "all".to_string(), |slot| slot.to_string())
}

fn bin_start_secs(bin: usize) -> f64 {
    (bin as u64 * BIN_MS) as f64 / 1_000.0
}

fn bars(arrivals: &Arrivals, width: usize) -> String {
    let columns = Scale::new(arrivals.bins.len(), width).columns(&arrivals.bins);
    let max = columns.iter().copied().max().unwrap_or(0).max(1);
    let bar = |&count: &u64| BARS[(count * (BARS.len() as u64 - 1)).div_ceil(max) as usize];
    columns.iter().map(bar).collect()
}

fn draw_table(f: &mut Frame, area: Rect, app: &mut App) {
    let slot_secs = app.attestations.all.bins.len() / BINS_PER_SEC;
    let title =
        format!(" attestations — verified pq votes by time into their slot, per {BIN_MS} ms ");
    let block = Block::default().borders(Borders::ALL).title(title);
    let bold = Style::default().add_modifier(Modifier::BOLD);
    let header = Row::new(vec![
        Cell::from("slot").style(bold),
        Cell::from("total").style(bold),
        Cell::from("late").style(bold),
        Cell::from("first").style(bold),
        Cell::from("peak").style(bold),
        Cell::from(format!("0s → {slot_secs}s")).style(bold.fg(ARRIVAL_COLOR)),
    ])
    .height(1);

    let bars_width = area.width.saturating_sub(FIXED_COLUMNS + 2) as usize;
    let rows: Vec<Row> =
        app.attestations_display_order
            .iter()
            .map(|&row| {
                let arrivals = selected(app, row);
                let first = arrivals.bins.iter().position(|&count| count > 0);
                let peak = (arrivals.bins.iter().enumerate())
                    .max_by_key(|&(bin, &count)| (count, usize::MAX - bin))
                    .filter(|&(_, &count)| count > 0);
                let style = if row == app.attestations_selected {
                    Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                Row::new(vec![
                    Cell::from(row_label(row)),
                    Cell::from(format!("{:>7}", arrivals.total())),
                    Cell::from(format!("{:>5}", arrivals.late)),
                    Cell::from(first.map_or_else(
                        || "·".to_string(),
                        |bin| format!("{:.1}s", bin_start_secs(bin)),
                    )),
                    Cell::from(peak.map_or_else(
                        || "·".to_string(),
                        |(bin, count)| format!("{count} @ {:.1}s", bin_start_secs(bin)),
                    )),
                    Cell::from(bars(arrivals, bars_width))
                        .style(Style::default().fg(ARRIVAL_COLOR)),
                ])
                .height(1)
                .style(style)
            })
            .collect();

    let widths = [
        Constraint::Length(10),
        Constraint::Length(9),
        Constraint::Length(7),
        Constraint::Length(8),
        Constraint::Length(15),
        Constraint::Min(0),
    ];
    let table = Table::new(rows, widths).header(header).block(block);
    let position = app
        .attestations_display_order
        .iter()
        .position(|&row| row == app.attestations_selected)
        .unwrap_or(0);
    app.attestations_table_state.select(Some(position));
    f.render_stateful_widget(table, area, &mut app.attestations_table_state);
}

/// One label per second, where it fits, under the column its second starts in.
fn seconds_axis(scale: &Scale, columns: usize) -> String {
    let mut axis = vec![' '; columns];
    let mut free_from = 0;
    let mut labelled = None;
    for column in 0..columns {
        let second = scale.bin_of(column) / BINS_PER_SEC;
        if labelled == Some(second) {
            continue;
        }
        labelled = Some(second);
        let label = format!("{second}s");
        if column >= free_from && column + label.len() <= columns {
            label.chars().enumerate().for_each(|(i, c)| axis[column + i] = c);
            free_from = column + label.len() + 1;
        }
    }
    axis.into_iter().collect()
}

fn draw_plot(f: &mut Frame, area: Rect, app: &App) {
    let arrivals = selected(app, app.attestations_selected);
    let title = format!(
        " slot {} — arrivals per {BIN_MS} ms — total {}, late {} ",
        row_label(app.attestations_selected),
        arrivals.total(),
        arrivals.late
    );
    let block = Block::default().borders(Borders::ALL).title(title);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let [bars_area, axis_area] =
        Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).areas(inner);
    let scale = Scale::new(arrivals.bins.len(), inner.width as usize);
    let columns = scale.columns(&arrivals.bins);
    f.render_widget(
        Paragraph::new(seconds_axis(&scale, columns.len()))
            .style(Style::default().fg(Color::DarkGray)),
        axis_area,
    );
    f.render_widget(
        Sparkline::default().data(&columns).style(Style::default().fg(ARRIVAL_COLOR)),
        bars_area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bins_spread_over_wide_areas_and_merge_into_narrow_ones() {
        let bins = [1, 2, 3, 4];
        let wide = Scale::new(bins.len(), 9);
        assert_eq!(wide.columns(&bins), [1, 1, 2, 2, 3, 3, 4, 4]);
        assert_eq!(wide.bin_of(5), 2);

        let narrow = Scale::new(bins.len(), 3);
        assert_eq!(narrow.columns(&bins), [3, 7]);
        assert_eq!(narrow.bin_of(1), 2);
    }

    #[test]
    fn axis_labels_each_second_that_fits() {
        let scale = Scale::new(3 * BINS_PER_SEC, 3 * BINS_PER_SEC);
        let axis = seconds_axis(&scale, 3 * BINS_PER_SEC);
        assert_eq!(axis, "0s        1s        2s        ");
    }
}
