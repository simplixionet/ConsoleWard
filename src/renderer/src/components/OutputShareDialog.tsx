// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Simplixio — Stanislav Opletal <info@simplixio.net>

import { useEffect, useMemo, useRef, useState } from 'react'
import type { ShareRequest } from '@shared/types'
import { EXCERPT_LINES, lastLines } from '@shared/excerpt'
import {
  MAX_HITS_PER_PATTERN,
  MAX_SCAN_CHARS,
  scanSecrets,
  summarizeSecrets
} from '@shared/secretPatterns'
import { useT } from '../i18n'
import { useArmedAfterPaint } from '../armDelay'
import { terminalSelection } from '../terminalBus'

/**
 * Co z výstupu odejde AI — ve třech krocích.
 *
 * Původní podoba nasypala celý buffer do textarey a nabídla „odeslat vše".
 * Tisíc řádků nikdo nečte, takže se to odklikávalo a zvýrazňování tajemství
 * bylo k ničemu: podbarvit tři sta míst v textu, který se stejně nečte, není
 * ochrana, jen ozdoba. Proto se teď nejdřív vybírá **co**, a teprve to krátké
 * se kontroluje.
 *
 * Klíčové je, že žádný krok neumí odeslat celý buffer. Kdo chce poslat všechno,
 * musí to všechno v konzoli označit — a přitom to uvidí.
 */

type Stage = 'choose' | 'picking' | 'review'

interface Props {
  request: ShareRequest
  onAnswer: (shared: boolean, text: string) => void
  /** Přepne hlavní okno na relaci, ze které se vybírá. */
  onShowSession: (sessionId: string) => void
}

export default function OutputShareDialog({ request, onAnswer, onShowSession }: Props) {
  const [stage, setStage] = useState<Stage>('choose')
  const [excerpt, setExcerpt] = useState('')

  /*
   * Every stage is its own component, and that is load-bearing rather than
   * tidiness: `useArmedAfterPaint` starts its clock on mount, so a stage that
   * appears under a cursor which has just clicked the button now occupying that
   * spot gets its own arming delay. Rendered as one component with a `stage`
   * variable, the arm would expire once at the start and the second half of a
   * double click could carry straight through to "send".
   */
  if (stage === 'picking') {
    return (
      <PickStage
        request={request}
        onBack={() => setStage('choose')}
        onCancel={() => onAnswer(false, '')}
        onPicked={(text) => {
          setExcerpt(text)
          setStage('review')
        }}
      />
    )
  }

  if (stage === 'review') {
    return (
      <ReviewStage
        request={request}
        initialText={excerpt}
        onBack={() => setStage('choose')}
        onAnswer={onAnswer}
      />
    )
  }

  return (
    <ChooseStage
      request={request}
      onPickInConsole={() => {
        onShowSession(request.sessionId)
        setStage('picking')
      }}
      onLastLines={() => {
        setExcerpt(lastLines(request.text, EXCERPT_LINES))
        setStage('review')
      }}
      onNothing={() => onAnswer(false, '')}
    />
  )
}

/* --------------------------------------------------------------- 1. výběr */

function ChooseStage({
  request,
  onPickInConsole,
  onLastLines,
  onNothing
}: {
  request: ShareRequest
  onPickInConsole: () => void
  onLastLines: () => void
  onNothing: () => void
}) {
  const t = useT()
  /*
   * No `armed` gate here on purpose: not one button on this stage sends
   * anything. That is the point of splitting the dialog — a stray click on a
   * window that just raised itself can no longer leak output, it can at worst
   * open the review step, which sends nothing until it is clicked again.
   */
  const canPick = terminalSelection(request.sessionId) !== null
  const hasText = request.text.length > 0

  return (
    <div className="modal-backdrop">
      <div className="modal choose-modal">
        <div className="modal-head">
          <h2>{titleFor(request, t)}</h2>
        </div>

        <div className="modal-body">
          <div className="approval-meta">
            <div>
              <span className="meta-label">{t('mcp.session')}</span>
              <span className="meta-value">{request.sessionName}</span>
            </div>
          </div>

          <div>
            <div className="meta-label">{t('mcp.aiReason')}</div>
            <div className="ai-reason">{request.reason || t('mcp.noReason')}</div>
          </div>

          {request.autoShareOverridden && (
            <div className="warn-box danger-box">{t('mcp.autoShareOverridden')}</div>
          )}

          <div className="hint">{t('mcp.chooseHint')}</div>

          {!canPick && <div className="warn-box">{t('mcp.pickUnavailable')}</div>}
        </div>

        <div className="modal-foot">
          <button className="btn" autoFocus onClick={onNothing}>
            {t('mcp.sendNothing')}
          </button>
          <button className="btn" disabled={!hasText} onClick={onLastLines}>
            {t('mcp.lastLines', { count: EXCERPT_LINES })}
          </button>
          <button className="btn primary" disabled={!canPick} onClick={onPickInConsole}>
            {t('mcp.pickInConsole')}
          </button>
        </div>
      </div>
    </div>
  )
}

/* ------------------------------------------------- 2. označování v konzoli */

/** Jak často se kontroluje, že terminál pořád existuje. Levné — sáhnutí do Mapy. */
const LOST_POLL_MS = 500

function PickStage({
  request,
  onPicked,
  onBack,
  onCancel
}: {
  request: ShareRequest
  onPicked: (text: string) => void
  onBack: () => void
  onCancel: () => void
}) {
  const t = useT()
  const [selected, setSelected] = useState('')
  const [lost, setLost] = useState(false)

  useEffect(() => {
    const source = terminalSelection(request.sessionId)
    if (!source) {
      setLost(true)
      return
    }
    const read = (): void => setSelected(source.read())
    /*
     * Wipe whatever was highlighted before the dialog opened. A selection the
     * human made ten minutes ago for some unrelated reason is not consent, and
     * leaving it in place would arm "continue" the moment this panel appears —
     * exactly the accident the "disabled until something is selected" rule
     * exists to prevent.
     */
    try {
      source.clear()
    } catch {
      /* nevadí, přečte se stejně */
    }
    read()
    const unsubscribe = source.subscribe(read)

    /*
     * Losing the console mid-selection has to be looked for, because nothing
     * announces it: the registry has no "gone" event, and a disposed xterm does
     * not fail on read — it stops reporting selection changes and answers with
     * an empty string. Left unwatched, the panel would sit at "nothing selected
     * yet" forever, which reads as "you have not highlighted anything" when the
     * truth is "there is nothing left to highlight".
     */
    let watch = 0
    const stop = (): void => {
      window.clearInterval(watch)
      unsubscribe()
    }
    watch = window.setInterval(() => {
      if (terminalSelection(request.sessionId) === source) return
      stop()
      // Co bylo označeno v mezitím zavřené konzoli, dál nejde — „continue" je na nule zamčené.
      setSelected('')
      setLost(true)
    }, LOST_POLL_MS)

    return stop
  }, [request.sessionId])

  const chars = selected.length
  const lines = selected === '' ? 0 : selected.split('\n').length

  return (
    <div className="pick-panel">
      <div className="pick-head">
        <span className="pick-title">{t('mcp.pickTitle')}</span>
        <span className="pick-session">{request.sessionName}</span>
      </div>

      <div className="pick-reason">{request.reason || t('mcp.noReason')}</div>

      {lost ? (
        <div className="warn-box danger-box">{t('mcp.pickLost')}</div>
      ) : (
        <div className="pick-hint">{t('mcp.pickHint')}</div>
      )}

      <div className="pick-count">
        {chars > 0 ? (
          <>
            {t('mcp.pickLines', { count: lines })} · {t('mcp.pickChars', { count: chars })}
          </>
        ) : (
          t('mcp.pickNothingYet')
        )}
      </div>

      <div className="pick-foot">
        <button className="btn small" onClick={onBack}>
          {t('mcp.back')}
        </button>
        <div className="spacer" />
        <button className="btn small" onClick={onCancel}>
          {t('mcp.sendNothing')}
        </button>
        <button
          className="btn small primary"
          disabled={chars === 0}
          onClick={() => onPicked(selected)}
        >
          {t('mcp.continue')}
        </button>
      </div>
    </div>
  )
}

/* ------------------------------------------------------------ 3. kontrola */

function ReviewStage({
  request,
  initialText,
  onBack,
  onAnswer
}: {
  request: ShareRequest
  initialText: string
  onBack: () => void
  onAnswer: (shared: boolean, text: string) => void
}) {
  const t = useT()
  const armed = useArmedAfterPaint()
  const [text, setText] = useState(initialText)
  const [selection, setSelection] = useState<{ start: number; end: number }>({ start: 0, end: 0 })
  const areaRef = useRef<HTMLTextAreaElement>(null)
  const backdropRef = useRef<HTMLDivElement>(null)

  /*
   * Sized once from the excerpt as it arrived, not from the live text: deleting
   * a couple of lines while redacting would otherwise shrink the field under
   * the cursor and slide the buttons up towards it.
   */
  const height = useMemo(() => reviewHeight(initialText), [initialText])

  const scan = useMemo(() => scanSecrets(text), [text])
  const matches = scan.matches
  const summary = useMemo(() => summarizeSecrets(matches), [matches])
  const highSeverity = matches.some((m) => m.severity === 'high')

  const selectedLength = Math.max(0, selection.end - selection.start)
  const hasSelection = selectedLength > 0

  function syncSelection(): void {
    const el = areaRef.current
    if (!el) return
    setSelection({ start: el.selectionStart, end: el.selectionEnd })
  }

  function syncScroll(): void {
    const el = areaRef.current
    const back = backdropRef.current
    if (!el || !back) return
    back.scrollTop = el.scrollTop
    back.scrollLeft = el.scrollLeft
  }

  function redactSelection(): void {
    if (!hasSelection) return
    const marker = t('mcp.redacted')
    const next = text.slice(0, selection.start) + marker + text.slice(selection.end)
    setText(next)
    const caret = selection.start + marker.length
    setSelection({ start: caret, end: caret })
    requestAnimationFrame(() => areaRef.current?.setSelectionRange(caret, caret))
  }

  const summaryText = summary
    .map(({ labelKey, count }) => (count > 1 ? `${count}× ${t(labelKey)}` : t(labelKey)))
    .join(', ')

  return (
    <div className="modal-backdrop">
      <div className="modal share-modal">
        <div className="modal-head">
          <h2>{titleFor(request, t)}</h2>
        </div>

        <div className="modal-body">
          <div className="approval-meta">
            <div>
              <span className="meta-label">{t('mcp.session')}</span>
              <span className="meta-value">{request.sessionName}</span>
            </div>
          </div>

          {/*
            The reason belongs on this step too, not only on the first one. This
            is where "send or not" is actually decided, and deciding it without
            what was asked for in front of you is deciding half of it.
          */}
          <div>
            <div className="meta-label">{t('mcp.aiReason')}</div>
            <div className="ai-reason">{request.reason || t('mcp.noReason')}</div>
          </div>

          {request.autoShareOverridden && (
            <div className="warn-box danger-box">{t('mcp.autoShareOverridden')}</div>
          )}

          {matches.length > 0 && (
            <div className={highSeverity ? 'warn-box danger-box' : 'warn-box'}>
              <b>{t('mcp.detectedLead')}</b> {summaryText}. {t('mcp.detectedTail')}
              {scan.incomplete && ` ${t('mcp.detectedIncomplete', { limit: MAX_HITS_PER_PATTERN })}`}
            </div>
          )}

          {scan.clipped && (
            <div className="warn-box danger-box">
              {t('mcp.scanClipped', { kb: MAX_SCAN_CHARS / 1024 })}
            </div>
          )}

          <div className="share-toolbar">
            <button
              type="button"
              className="btn small"
              disabled={!hasSelection}
              onClick={redactSelection}
              title={t('mcp.redactTitle')}
            >
              {t('mcp.redact')}
            </button>
            <div className="spacer" />
            <span className="share-count">
              {hasSelection
                ? t('mcp.selectedCount', { selected: selectedLength, total: text.length })
                : t('mcp.totalCount', { count: text.length })}
            </span>
          </div>

          {/*
            An estimate, not a measurement: a line that wraps takes more than
            one row, so a wide excerpt can still need scrolling. That is the
            acceptable half — the box is bounded at both ends, so the worst case
            is a short scroll, never a field collapsed to nothing or one that
            pushes the send buttons off screen.
          */}
          <div
            className="hl-wrap review-wrap"
            style={{ '--review-height': `${height}px` } as React.CSSProperties}
          >
            <div className="hl-backdrop" ref={backdropRef} aria-hidden="true">
              {renderHighlighted(text, matches)}
            </div>
            <textarea
              ref={areaRef}
              className="hl-input"
              value={text}
              spellCheck={false}
              onChange={(e) => {
                setText(e.target.value)
                syncSelection()
              }}
              onSelect={syncSelection}
              onKeyUp={syncSelection}
              onMouseUp={syncSelection}
              onScroll={syncScroll}
            />
          </div>

          <div className="hint">{t('mcp.shareHint')}</div>
        </div>

        <div className="modal-foot">
          <button className="btn" onClick={onBack}>
            {t('mcp.back')}
          </button>
          <div className="spacer" />
          <button className="btn" autoFocus onClick={() => onAnswer(false, '')}>
            {t('mcp.sendNothing')}
          </button>
          {/*
            Disabled on an empty excerpt for the same reason "continue" is: an
            approval that sends nothing is indistinguishable from a refusal to
            the model, but not to the human, who walks away believing they
            answered. Redacting everything is a refusal — say so with the other
            button.
          */}
          <button
            className="btn primary"
            disabled={!armed || text.length === 0}
            onClick={() => onAnswer(true, text)}
          >
            {t('mcp.send')}
          </button>
        </div>
      </div>
    </div>
  )
}

/** Řádkování 1.6 × 12px z .hl-input, plus vnitřní odsazení a rámeček. */
const REVIEW_LINE_PX = 19.2
const REVIEW_CHROME_PX = 22
const REVIEW_MIN_PX = 120
const REVIEW_MAX_PX = 320

function reviewHeight(text: string): number {
  const lines = text === '' ? 1 : text.split('\n').length
  const wanted = Math.round(lines * REVIEW_LINE_PX) + REVIEW_CHROME_PX
  return Math.min(REVIEW_MAX_PX, Math.max(REVIEW_MIN_PX, wanted))
}

function titleFor(request: ShareRequest, t: (key: string) => string): string {
  return request.origin === 'command_output' ? t('mcp.shareTitleOutput') : t('mcp.shareTitleRead')
}

function renderHighlighted(
  text: string,
  matches: { start: number; end: number; severity: 'high' | 'medium' }[]
): React.ReactNode[] {
  const nodes: React.ReactNode[] = []
  let pos = 0
  matches.forEach((m, i) => {
    if (m.start > pos) nodes.push(text.slice(pos, m.start))
    nodes.push(
      <mark key={i} className={`hl-${m.severity}`}>
        {text.slice(m.start, m.end)}
      </mark>
    )
    pos = m.end
  })
  // Koncová mezera drží poslední (prázdný) řádek, aby podbarvení nesjelo.
  nodes.push(text.slice(pos) + '\n ')
  return nodes
}
