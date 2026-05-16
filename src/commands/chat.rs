use std::io::{self, Stdout};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers, MouseEvent, MouseEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Paragraph, Wrap};
use ratatui::{Frame, Terminal};
use serde_json::{Value, json};

use crate::commands::local_http;

const CHAT_PATH: &str = "/v1/chat/completions";
const EVENT_POLL_INTERVAL: Duration = Duration::from_millis(50);
const REQUEST_TIMEOUT_GRACE_SECS: f64 = 5.0;
const BODY_PREVIEW_CHARS: usize = 500;
const THINK_OPEN_TAG: &str = "<think>";
const THINK_CLOSE_TAG: &str = "</think>";
const INPUT_PLACEHOLDER: &str = "Message...";
const INPUT_HEIGHT: u16 = 3;
const CHAT_PADDING: u16 = 1;
const WAIT_FRAMES: [&str; 4] = ["-", "\\", "|", "/"];

type ChatTerminal = Terminal<CrosstermBackend<Stdout>>;
type CompletionResult = std::result::Result<String, String>;

pub fn run(
    listen_addr: &str,
    model: &str,
    max_tokens: i32,
    timeout_secs: f64,
    verbose: bool,
) -> Result<()> {
    validate_options(model, max_tokens, timeout_secs)?;
    let _session = TerminalSession::enter()?;
    let mut terminal =
        Terminal::new(CrosstermBackend::new(io::stdout())).context("initialize chat terminal")?;
    let mut app = ChatApp::new(
        listen_addr.to_string(),
        model.to_string(),
        max_tokens,
        timeout_secs,
        verbose,
    );
    run_loop(&mut terminal, &mut app)
}

fn validate_options(model: &str, max_tokens: i32, timeout_secs: f64) -> Result<()> {
    if model.trim().is_empty() {
        anyhow::bail!("chat model must not be empty");
    }
    if max_tokens <= 0 {
        anyhow::bail!("chat max_tokens must be greater than zero");
    }
    if !timeout_secs.is_finite() || timeout_secs <= 0.0 {
        anyhow::bail!("chat timeout must be a finite positive number");
    }
    Ok(())
}

fn run_loop(terminal: &mut ChatTerminal, app: &mut ChatApp) -> Result<()> {
    loop {
        app.receive_completion();
        terminal
            .draw(|frame| render(frame, app))
            .context("draw chat UI")?;
        if app.should_quit {
            return Ok(());
        }
        if event::poll(EVENT_POLL_INTERVAL).context("poll terminal event")? {
            match event::read().context("read terminal event")? {
                Event::Key(key) if key.kind == KeyEventKind::Press => handle_key(app, key),
                Event::Mouse(mouse) => handle_mouse(app, mouse),
                _ => {}
            }
        }
    }
}

fn handle_key(app: &mut ChatApp, key: KeyEvent) {
    match key.code {
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.should_quit = true;
        }
        KeyCode::Char('t') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.show_thinking = !app.show_thinking;
        }
        KeyCode::Esc => {
            app.should_quit = true;
        }
        KeyCode::Enter => app.submit(),
        KeyCode::Backspace => {
            app.input.pop();
        }
        KeyCode::PageUp => {
            app.scroll_lines = app.scroll_lines.saturating_add(8);
        }
        KeyCode::PageDown => {
            app.scroll_lines = app.scroll_lines.saturating_sub(8);
        }
        KeyCode::Char(value)
            if !key.modifiers.contains(KeyModifiers::CONTROL)
                && !key.modifiers.contains(KeyModifiers::ALT) =>
        {
            app.input.push(value);
        }
        _ => {}
    }
}

const fn handle_mouse(app: &mut ChatApp, mouse: MouseEvent) {
    match mouse.kind {
        MouseEventKind::ScrollUp => app.scroll_up(3),
        MouseEventKind::ScrollDown => app.scroll_down(3),
        _ => {}
    }
}

fn render(frame: &mut Frame<'_>, app: &ChatApp) {
    let layout = ChatLayout::split(frame.area());
    MessageList::new(app, frame.count()).render(frame, layout.messages);
    InputBox::new(&app.input).render(frame, layout.input);
    StatusLine::new(app).render(frame, layout.status);
}

#[derive(Clone, Copy, Debug)]
struct ChatLayout {
    messages: Rect,
    status: Rect,
    input: Rect,
}

impl ChatLayout {
    fn split(area: Rect) -> Self {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(1),
                Constraint::Length(INPUT_HEIGHT),
                Constraint::Length(1),
            ])
            .split(area);
        Self {
            messages: chunks[0],
            input: chunks[1],
            status: chunks[2],
        }
    }
}

struct MessageList<'a> {
    app: &'a ChatApp,
    animation_frame: usize,
}

impl<'a> MessageList<'a> {
    const fn new(app: &'a ChatApp, animation_frame: usize) -> Self {
        Self {
            app,
            animation_frame,
        }
    }

    fn render(&self, frame: &mut Frame<'_>, area: Rect) {
        let area = padded_chat_area(area);
        let lines = self.visible_lines(area);
        let paragraph = Paragraph::new(Text::from(lines)).wrap(Wrap { trim: false });
        frame.render_widget(paragraph, area);
    }

    fn visible_lines(&self, area: Rect) -> Vec<Line<'static>> {
        let lines = self.lines();
        let visible_height = usize::from(area.height);
        if visible_height == 0 {
            return Vec::new();
        }
        let max_scroll = lines.len().saturating_sub(visible_height);
        let scroll_lines = self.app.scroll_lines.min(max_scroll);
        let end = lines.len().saturating_sub(scroll_lines);
        let start = end.saturating_sub(visible_height);
        lines[start..end].to_vec()
    }

    fn lines(&self) -> Vec<Line<'static>> {
        if self.app.messages.is_empty() && self.app.pending.is_none() {
            return vec![Line::from(Span::styled(
                "Type a message and press Enter.",
                Style::default().fg(Color::DarkGray),
            ))];
        }

        let mut lines = Vec::new();
        for (index, message) in self.app.messages.iter().enumerate() {
            append_message_lines(&mut lines, message, self.app.show_thinking);
            if index + 1 < self.app.messages.len() || self.app.pending.is_some() {
                push_blank_line_if_needed(&mut lines);
            }
        }

        if self.app.pending.is_some() {
            lines.push(Message::header_line_for(MessageRole::Assistant));
            lines.push(waiting_line(self.animation_frame));
        }

        lines
    }
}

struct StatusLine<'a> {
    app: &'a ChatApp,
}

impl<'a> StatusLine<'a> {
    const fn new(app: &'a ChatApp) -> Self {
        Self { app }
    }

    fn render(&self, frame: &mut Frame<'_>, area: Rect) {
        let status = if self.app.show_thinking {
            "Enter send | Ctrl-T hide thinking | scroll/PageUp/PageDown | Esc quit".to_string()
        } else {
            "Enter send | Ctrl-T show thinking | scroll/PageUp/PageDown | Esc quit".to_string()
        };
        let paragraph = Paragraph::new(status).style(Style::default().fg(Color::DarkGray));
        frame.render_widget(paragraph, area);
    }
}

struct InputBox<'a> {
    input: &'a str,
}

impl<'a> InputBox<'a> {
    const fn new(input: &'a str) -> Self {
        Self { input }
    }

    fn render(&self, frame: &mut Frame<'_>, area: Rect) {
        let field_style = Style::default().fg(Color::White).bg(Color::Rgb(31, 35, 44));
        frame.render_widget(Block::default().style(field_style), area);

        let input_area = padded_input_area(area);
        let input = trailing_chars(self.input, usize::from(input_area.width));
        let input_line = if input.is_empty() {
            Line::from(Span::styled(INPUT_PLACEHOLDER, field_style.fg(Color::Gray)))
        } else {
            Line::from(Span::styled(input.as_str().to_string(), field_style))
        };
        let paragraph = Paragraph::new(input_line).style(field_style);
        frame.render_widget(paragraph, input_area);

        if input_area.width > 0 && input_area.height > 0 {
            let input_len = input.chars().count();
            let cursor_offset = usize_to_u16_saturating(input_len).min(input_area.width);
            frame.set_cursor_position((input_area.x.saturating_add(cursor_offset), input_area.y));
        }
    }
}

fn append_message_lines(lines: &mut Vec<Line<'static>>, message: &Message, show_thinking: bool) {
    lines.push(message.header_line());
    let content_lines = message.content_lines(show_thinking);
    if content_lines.is_empty() {
        lines.push(Line::from(Span::raw(String::new())));
    } else {
        lines.extend(content_lines);
    }
}

fn waiting_line(animation_frame: usize) -> Line<'static> {
    let frame = WAIT_FRAMES[(animation_frame / 4) % WAIT_FRAMES.len()];
    Line::from(Span::styled(
        format!("waiting {frame}"),
        Style::default().fg(Color::DarkGray),
    ))
}

fn push_blank_line_if_needed(lines: &mut Vec<Line<'static>>) {
    if lines.last().is_some_and(|line| line.width() == 0) {
        return;
    }
    lines.push(Line::from(""));
}

const fn padded_chat_area(area: Rect) -> Rect {
    inset_area(area, CHAT_PADDING, CHAT_PADDING)
}

const fn padded_input_area(area: Rect) -> Rect {
    inset_area(area, 1, 1)
}

const fn inset_area(area: Rect, horizontal: u16, vertical: u16) -> Rect {
    if area.width <= horizontal.saturating_mul(2) || area.height <= vertical.saturating_mul(2) {
        return area;
    }
    Rect {
        x: area.x + horizontal,
        y: area.y + vertical,
        width: area.width - horizontal.saturating_mul(2),
        height: area.height - vertical.saturating_mul(2),
    }
}

fn trailing_chars(value: &str, max_chars: usize) -> String {
    let char_count = value.chars().count();
    if char_count <= max_chars {
        return value.to_string();
    }
    value.chars().skip(char_count - max_chars).collect()
}

fn usize_to_u16_saturating(value: usize) -> u16 {
    u16::try_from(value).unwrap_or(u16::MAX)
}

#[derive(Debug)]
struct ChatApp {
    listen_addr: String,
    model: String,
    max_tokens: i32,
    timeout_secs: f64,
    verbose: bool,
    messages: Vec<Message>,
    input: String,
    pending: Option<Receiver<CompletionResult>>,
    scroll_lines: usize,
    show_thinking: bool,
    should_quit: bool,
}

impl ChatApp {
    const fn new(
        listen_addr: String,
        model: String,
        max_tokens: i32,
        timeout_secs: f64,
        verbose: bool,
    ) -> Self {
        Self {
            listen_addr,
            model,
            max_tokens,
            timeout_secs,
            verbose,
            messages: Vec::new(),
            input: String::new(),
            pending: None,
            scroll_lines: 0,
            show_thinking: false,
            should_quit: false,
        }
    }

    fn submit(&mut self) {
        if self.pending.is_some() {
            return;
        }
        let content = self.input.trim().to_string();
        if content.is_empty() {
            return;
        }

        self.input.clear();
        self.messages.push(Message::new(MessageRole::User, content));
        self.scroll_lines = 0;

        let request_messages = self.request_messages();
        let listen_addr = self.listen_addr.clone();
        let model = self.model.clone();
        let max_tokens = self.max_tokens;
        let timeout_secs = self.timeout_secs;
        let verbose = self.verbose;
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let result = request_completion(
                &listen_addr,
                &model,
                max_tokens,
                timeout_secs,
                verbose,
                request_messages,
            )
            .map_err(|error| format!("{error:#}"));
            let _ignored = sender.send(result);
        });
        self.pending = Some(receiver);
    }

    fn receive_completion(&mut self) {
        let Some(receiver) = &self.pending else {
            return;
        };
        let result = match receiver.try_recv() {
            Ok(result) => result,
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => {
                Err("chat request worker stopped before sending a response".to_string())
            }
        };
        self.pending = None;
        match result {
            Ok(content) => self
                .messages
                .push(Message::new(MessageRole::Assistant, content)),
            Err(error) => self.messages.push(Message::new(MessageRole::Error, error)),
        }
        self.scroll_lines = 0;
    }

    const fn scroll_up(&mut self, lines: usize) {
        self.scroll_lines = self.scroll_lines.saturating_add(lines);
    }

    const fn scroll_down(&mut self, lines: usize) {
        self.scroll_lines = self.scroll_lines.saturating_sub(lines);
    }

    fn request_messages(&self) -> Vec<RequestMessage> {
        self.messages
            .iter()
            .filter_map(Message::to_request_message)
            .collect()
    }
}

#[derive(Debug)]
struct Message {
    role: MessageRole,
    content: String,
}

impl Message {
    const fn new(role: MessageRole, content: String) -> Self {
        Self { role, content }
    }

    fn header_line(&self) -> Line<'static> {
        Self::header_line_for(self.role)
    }

    fn header_line_for(role: MessageRole) -> Line<'static> {
        let (label, color) = match role {
            MessageRole::User => ("You", Color::Cyan),
            MessageRole::Assistant => ("Assistant", Color::Green),
            MessageRole::Error => ("Error", Color::Red),
        };
        Line::from(Span::styled(
            label,
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ))
    }

    fn to_request_message(&self) -> Option<RequestMessage> {
        let role = match self.role {
            MessageRole::User => "user",
            MessageRole::Assistant => "assistant",
            MessageRole::Error => return None,
        };
        Some(RequestMessage {
            role,
            content: self.content.clone(),
        })
    }

    fn content_lines(&self, show_thinking: bool) -> Vec<Line<'static>> {
        let mut lines = Vec::new();
        let mut trim_next_text_leading_blank_lines = false;
        for part in split_think_blocks(&self.content) {
            match part {
                ContentPart::Text(text) => {
                    let text = if trim_next_text_leading_blank_lines {
                        trim_leading_line_breaks(text)
                    } else {
                        text
                    };
                    trim_next_text_leading_blank_lines = false;
                    push_text_lines(&mut lines, text, Style::default());
                }
                ContentPart::Think(text) if show_thinking => {
                    trim_next_text_leading_blank_lines = false;
                    let style = Style::default().fg(Color::DarkGray);
                    push_text_lines(&mut lines, THINK_OPEN_TAG, style);
                    push_text_lines(&mut lines, text, style);
                    push_text_lines(&mut lines, THINK_CLOSE_TAG, style);
                }
                ContentPart::Think(_) => {
                    lines.push(Line::from(Span::styled(
                        "thinking",
                        Style::default()
                            .fg(Color::White)
                            .add_modifier(Modifier::BOLD),
                    )));
                    lines.push(Line::from(""));
                    trim_next_text_leading_blank_lines = true;
                }
            }
        }
        lines
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ContentPart<'a> {
    Text(&'a str),
    Think(&'a str),
}

fn split_think_blocks(mut content: &str) -> Vec<ContentPart<'_>> {
    let mut parts = Vec::new();
    loop {
        let Some(open_offset) = content.find(THINK_OPEN_TAG) else {
            if !content.is_empty() {
                parts.push(ContentPart::Text(content));
            }
            return parts;
        };

        let before = &content[..open_offset];
        if !before.is_empty() {
            parts.push(ContentPart::Text(before));
        }

        let after_open = &content[open_offset + THINK_OPEN_TAG.len()..];
        let Some(close_offset) = after_open.find(THINK_CLOSE_TAG) else {
            parts.push(ContentPart::Think(after_open));
            return parts;
        };

        parts.push(ContentPart::Think(&after_open[..close_offset]));
        content = &after_open[close_offset + THINK_CLOSE_TAG.len()..];
    }
}

fn push_text_lines(lines: &mut Vec<Line<'static>>, text: &str, style: Style) {
    for line in text.lines() {
        lines.push(Line::from(Span::styled(line.to_string(), style)));
    }
}

fn trim_leading_line_breaks(text: &str) -> &str {
    text.trim_start_matches(['\r', '\n'])
}

#[derive(Clone, Copy, Debug)]
enum MessageRole {
    User,
    Assistant,
    Error,
}

#[derive(Debug)]
struct RequestMessage {
    role: &'static str,
    content: String,
}

fn request_completion(
    listen_addr: &str,
    model: &str,
    max_tokens: i32,
    timeout_secs: f64,
    verbose: bool,
    messages: Vec<RequestMessage>,
) -> Result<String> {
    let body = json!({
        "model": model,
        "messages": messages
            .into_iter()
            .map(|message| json!({
                "role": message.role,
                "content": message.content,
            }))
            .collect::<Vec<_>>(),
        "max_tokens": max_tokens,
        "timeout": timeout_secs,
    });
    let body = serde_json::to_vec(&body).context("serialize chat request JSON")?;
    let http_timeout = Duration::try_from_secs_f64(timeout_secs + REQUEST_TIMEOUT_GRACE_SECS)
        .context("convert chat timeout to duration")?;
    let response = local_http::post_json(listen_addr, CHAT_PATH, &body, http_timeout)?;
    if !(200..300).contains(&response.status_code) {
        anyhow::bail!(
            "local server returned HTTP {}: {}",
            response.status_code,
            body_preview(&response.body)
        );
    }
    if verbose {
        parse_response_content(&response.body).with_context(|| {
            format!(
                "parse response from {}",
                local_http::url(listen_addr, CHAT_PATH)
            )
        })
    } else {
        parse_response_content(&response.body)
    }
}

fn parse_response_content(body: &str) -> Result<String> {
    let value: Value = serde_json::from_str(body).context("parse chat response JSON")?;
    let choices = value
        .get("choices")
        .and_then(Value::as_array)
        .context("chat response is missing choices array")?;
    let choice = choices.first().context("chat response has no choices")?;
    let content = choice
        .get("message")
        .and_then(|message| message.get("content"))
        .and_then(Value::as_str)
        .or_else(|| choice.get("text").and_then(Value::as_str))
        .context("chat response is missing assistant content")?;
    Ok(content.to_string())
}

fn body_preview(body: &str) -> String {
    let mut preview = body.chars().take(BODY_PREVIEW_CHARS).collect::<String>();
    if body.chars().count() > BODY_PREVIEW_CHARS {
        preview.push_str("...");
    }
    preview
}

struct TerminalSession;

impl TerminalSession {
    fn enter() -> Result<Self> {
        enable_raw_mode().context("enable terminal raw mode")?;
        if let Err(error) = execute!(io::stdout(), EnterAlternateScreen, EnableMouseCapture) {
            let _ignored = execute!(io::stdout(), DisableMouseCapture, LeaveAlternateScreen);
            let _ignored = disable_raw_mode();
            return Err(error).context("enter terminal alternate screen");
        }
        Ok(Self)
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        let _ignored = disable_raw_mode();
        let _ignored = execute!(io::stdout(), DisableMouseCapture, LeaveAlternateScreen);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_think_blocks_separates_visible_and_thinking_text() {
        let parts = split_think_blocks("hello <think>hidden</think> world");

        assert_eq!(
            parts,
            vec![
                ContentPart::Text("hello "),
                ContentPart::Think("hidden"),
                ContentPart::Text(" world"),
            ]
        );
    }

    #[test]
    fn split_think_blocks_treats_unclosed_think_as_thinking_text() {
        let parts = split_think_blocks("hello <think>hidden");

        assert_eq!(
            parts,
            vec![ContentPart::Text("hello "), ContentPart::Think("hidden")]
        );
    }

    #[test]
    fn padded_input_area_adds_one_cell_padding_on_each_side() {
        let area = Rect::new(3, 5, 20, 3);
        let padded = padded_input_area(area);

        assert_eq!(padded, Rect::new(4, 6, 18, 1));
    }

    #[test]
    fn chat_layout_places_status_line_below_input() {
        let layout = ChatLayout::split(Rect::new(0, 0, 80, 24));

        assert_eq!(layout.messages, Rect::new(0, 0, 80, 20));
        assert_eq!(layout.input, Rect::new(0, 20, 80, 3));
        assert_eq!(layout.status, Rect::new(0, 23, 80, 1));
    }

    #[test]
    fn padded_chat_area_adds_one_cell_padding_on_each_side() {
        let area = Rect::new(0, 0, 80, 20);
        let padded = padded_chat_area(area);

        assert_eq!(padded, Rect::new(1, 1, 78, 18));
    }

    #[test]
    fn collapsed_thinking_adds_label_and_blank_line() {
        let message = Message::new(
            MessageRole::Assistant,
            "<think>hidden</think>done".to_string(),
        );
        let lines = message.content_lines(false);

        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0].width(), "thinking".len());
        assert_eq!(lines[1].width(), 0);
        assert_eq!(lines[2].width(), "done".len());
    }

    #[test]
    fn collapsed_thinking_removes_extra_blank_lines_after_close_tag() {
        let message = Message::new(
            MessageRole::Assistant,
            "<think>hidden</think>\n\n\ndone".to_string(),
        );
        let lines = message.content_lines(false);

        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0].width(), "thinking".len());
        assert_eq!(lines[1].width(), 0);
        assert_eq!(lines[2].width(), "done".len());
    }
}
