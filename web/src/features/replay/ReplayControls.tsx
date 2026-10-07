import { IconButton } from '../../components/Button';
import { Select } from '../../components/Form';
import { SPEEDS, type Speed } from './engine';
import type { Playback } from './usePlayback';

export function ReplayControls({ playback, length }: { playback: Playback; length: number }) {
  const atStart = playback.index <= -1;
  const atEnd = playback.index >= length - 1;
  return (
    <div className="replay-controls" role="group" aria-label="Playback controls">
      <IconButton icon="stepBack" label="Step back (←)" disabled={atStart} onClick={playback.stepBack} />
      <IconButton
        icon="stepForward"
        label="Step forward (→)"
        disabled={atEnd}
        onClick={playback.stepForward}
      />
      <IconButton icon="pause" label="Pause (Space)" disabled={!playback.playing} onClick={playback.pause} />
      <IconButton
        icon="fastForward"
        label={atEnd ? 'Play from the beginning (Space)' : 'Play (Space)'}
        active={playback.playing}
        disabled={length === 0 || playback.playing}
        onClick={playback.play}
      />
      <Select
        aria-label="Playback speed"
        className="select--compact"
        value={String(playback.speed)}
        options={SPEEDS.map((speed) => ({ value: String(speed), label: `${speed}x` }))}
        onChange={(event) => playback.setSpeed(Number(event.target.value) as Speed)}
      />
      <span className="replay-controls__position tabular small muted" aria-live="off">
        step {Math.max(0, playback.index + 1)} / {length}
      </span>
    </div>
  );
}
