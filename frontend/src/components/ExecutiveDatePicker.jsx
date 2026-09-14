import React, { useState, useEffect, useRef, useMemo } from 'react';

/**
 * Format a Date object as YYYY-MM-DD in local time
 */
function formatDateKey(date) {
  if (!date) return '';
  const d = date instanceof Date ? date : new Date(date);
  if (isNaN(d.getTime())) return '';
  const year = d.getFullYear();
  const month = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

/**
 * Format a YYYY-MM-DD string into human-readable label (e.g. "14 Sep 2026")
 */
function formatDisplayDate(dateStr) {
  if (!dateStr) return '';
  try {
    const [y, m, d] = dateStr.split('-').map(Number);
    if (!y || !m || !d) return dateStr;
    const date = new Date(y, m - 1, d);
    return date.toLocaleDateString('en-US', {
      day: 'numeric',
      month: 'short',
      year: 'numeric'
    });
  } catch {
    return dateStr;
  }
}

const MONTH_NAMES = [
  'January', 'February', 'March', 'April', 'May', 'June',
  'July', 'August', 'September', 'October', 'November', 'December'
];

const WEEK_DAYS = ['Su', 'Mo', 'Tu', 'We', 'Th', 'Fr', 'Sa'];

export default function ExecutiveDatePicker({
  startDate = '',
  endDate = '',
  onChange,
  availableDateSet = new Set(),
  isCustomActive = false,
  className = ''
}) {
  const [isOpen, setIsOpen] = useState(false);
  const [validationError, setValidationError] = useState(null);
  const containerRef = useRef(null);

  // Calendar view navigation state (year & month)
  const initialView = useMemo(() => {
    if (startDate) {
      const [y, m] = startDate.split('-').map(Number);
      if (y && m) return { year: y, month: m - 1 };
    }
    const today = new Date();
    return { year: today.getFullYear(), month: today.getMonth() };
  }, [startDate]);

  const [viewYear, setViewYear] = useState(initialView.year);
  const [viewMonth, setViewMonth] = useState(initialView.month);

  // Range selection temporary state while user is picking dates
  const [selectionStart, setSelectionStart] = useState(startDate);
  const [selectionEnd, setSelectionEnd] = useState(endDate);
  const [hoverDate, setHoverDate] = useState(null);
  const [isPickingEnd, setIsPickingEnd] = useState(false);

  // Synchronize state during render when parent filter props change (React recommended pattern)
  const [prevStart, setPrevStart] = useState(startDate);
  const [prevEnd, setPrevEnd] = useState(endDate);

  if (startDate !== prevStart || endDate !== prevEnd) {
    setPrevStart(startDate);
    setPrevEnd(endDate);
    setSelectionStart(startDate);
    setSelectionEnd(endDate);
    setValidationError(null);
  }

  // Synchronize when opening
  const handleToggleOpen = () => {
    if (!isOpen) {
      setSelectionStart(startDate);
      setSelectionEnd(endDate);
      setIsPickingEnd(false);
      setValidationError(null);
      if (startDate) {
        const [y, m] = startDate.split('-').map(Number);
        if (y && m) {
          setViewYear(y);
          setViewMonth(m - 1);
        }
      }
    }
    setIsOpen((prev) => !prev);
  };

  // Close calendar popover on outside click or Escape key
  useEffect(() => {
    const handleClickOutside = (e) => {
      if (containerRef.current && !containerRef.current.contains(e.target)) {
        setIsOpen(false);
        setIsPickingEnd(false);
      }
    };
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        setIsOpen(false);
        setIsPickingEnd(false);
      }
    };
    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
      document.addEventListener('keydown', handleKeyDown);
    }
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [isOpen]);

  // Navigate months
  const handlePrevMonth = () => {
    if (viewMonth === 0) {
      setViewMonth(11);
      setViewYear((y) => y - 1);
    } else {
      setViewMonth((m) => m - 1);
    }
  };

  const handleNextMonth = () => {
    if (viewMonth === 11) {
      setViewMonth(0);
      setViewYear((y) => y + 1);
    } else {
      setViewMonth((m) => m + 1);
    }
  };

  const handleJumpToday = () => {
    const today = new Date();
    setViewYear(today.getFullYear());
    setViewMonth(today.getMonth());
  };

  // Generate calendar days for viewYear and viewMonth
  const calendarDays = useMemo(() => {
    const firstDay = new Date(viewYear, viewMonth, 1);
    const startDayOfWeek = firstDay.getDay(); // 0 (Sun) to 6 (Sat)
    const daysInCurrentMonth = new Date(viewYear, viewMonth + 1, 0).getDate();
    const daysInPrevMonth = new Date(viewYear, viewMonth, 0).getDate();

    const days = [];

    // Previous month padding days
    for (let i = startDayOfWeek - 1; i >= 0; i--) {
      const dayNum = daysInPrevMonth - i;
      const prevDate = new Date(viewYear, viewMonth - 1, dayNum);
      const key = formatDateKey(prevDate);
      days.push({
        date: prevDate,
        key,
        dayNum,
        isCurrentMonth: false,
        isPrevMonth: true
      });
    }

    // Current month days
    for (let i = 1; i <= daysInCurrentMonth; i++) {
      const curDate = new Date(viewYear, viewMonth, i);
      const key = formatDateKey(curDate);
      days.push({
        date: curDate,
        key,
        dayNum: i,
        isCurrentMonth: true
      });
    }

    // Next month padding days to complete grid (up to 42 cells or multiple of 7)
    const totalCells = days.length <= 35 ? 35 : 42;
    const remaining = totalCells - days.length;
    for (let i = 1; i <= remaining; i++) {
      const nextDate = new Date(viewYear, viewMonth + 1, i);
      const key = formatDateKey(nextDate);
      days.push({
        date: nextDate,
        key,
        dayNum: i,
        isCurrentMonth: false,
        isNextMonth: true
      });
    }

    return days;
  }, [viewYear, viewMonth]);

  // Range determination for styling
  const activeStart = selectionStart;
  const activeEnd = isPickingEnd && hoverDate ? (hoverDate < selectionStart ? selectionStart : hoverDate) : selectionEnd;
  const tentativeStart = isPickingEnd && hoverDate && hoverDate < selectionStart ? hoverDate : activeStart;

  // Handle clicking a day cell
  const handleDayClick = (dayKey) => {
    setValidationError(null);
    if (!isPickingEnd) {
      // First click: start new range
      setSelectionStart(dayKey);
      setSelectionEnd(dayKey);
      setIsPickingEnd(true);
    } else {
      // Second click: complete range
      let finalStart = selectionStart;
      let finalEnd = dayKey;
      if (dayKey < selectionStart) {
        finalStart = dayKey;
        finalEnd = selectionStart;
      }
      setSelectionStart(finalStart);
      setSelectionEnd(finalEnd);
      setIsPickingEnd(false);
      if (onChange) {
        onChange({ startDate: finalStart, endDate: finalEnd, isCustom: true });
      }
    }
  };

  // Reset filter handler
  const handlePresetAll = () => {
    setSelectionStart('');
    setSelectionEnd('');
    setValidationError(null);
    setIsPickingEnd(false);
    if (onChange) {
      onChange({ startDate: '', endDate: '', isCustom: false });
    }
    setIsOpen(false);
  };

  // Direct manual date input change
  const handleManualDateChange = (field, val) => {
    if (field === 'start') {
      setSelectionStart(val);
      if (val && selectionEnd && val > selectionEnd) {
        setValidationError('Start date cannot be after End date');
        return;
      }
      setValidationError(null);
      if (val && onChange) {
        onChange({
          startDate: val,
          endDate: selectionEnd && selectionEnd >= val ? selectionEnd : val,
          isCustom: true
        });
      }
    } else {
      setSelectionEnd(val);
      if (selectionStart && val && selectionStart > val) {
        setValidationError('Start date cannot be after End date');
        return;
      }
      setValidationError(null);
      if (val && onChange) {
        onChange({
          startDate: selectionStart && selectionStart <= val ? selectionStart : val,
          endDate: val,
          isCustom: true
        });
      }
    }
  };

  // Format label for trigger button
  const triggerLabel = useMemo(() => {
    if (!startDate && !endDate) {
      return 'All Available Dates';
    }
    if (startDate && (!endDate || startDate === endDate)) {
      return formatDisplayDate(startDate);
    }
    return `${formatDisplayDate(startDate)} – ${formatDisplayDate(endDate)}`;
  }, [startDate, endDate]);

  const hasActiveFilter = Boolean(startDate || endDate);

  return (
    <div className={`relative inline-block ${className}`} ref={containerRef}>
      {/* TRIGGER CONTROL BUTTON */}
      <div className={`inline-flex items-center rounded-lg shadow-2xs border transition-colors ${
        isCustomActive
          ? 'border-[#006591] dark:border-sky-500 bg-sky-50 dark:bg-sky-950/40 text-[#006591] dark:text-sky-300 ring-1.5 ring-[#006591]/40 dark:ring-sky-500/40'
          : 'border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-slate-800 dark:text-slate-200 hover:border-slate-300 dark:hover:border-slate-600 focus-within:ring-1.5 focus-within:ring-[#006591] dark:focus-within:ring-sky-500'
      }`}>
        <button
          type="button"
          onClick={handleToggleOpen}
          className="inline-flex items-center gap-2 pl-3 pr-2.5 py-1.5 text-xs font-semibold cursor-pointer select-none"
          aria-haspopup="dialog"
          aria-expanded={isOpen}
          title="Open calendar date filter"
        >
          <span className="material-symbols-outlined text-[16px] text-[#006591] dark:text-sky-400">
            calendar_month
          </span>
          <span className="font-sans font-semibold tracking-normal text-slate-800 dark:text-slate-100 whitespace-nowrap">
            {triggerLabel}
          </span>
          <span className="material-symbols-outlined text-[16px] text-slate-400 dark:text-slate-500">
            {isOpen ? 'expand_less' : 'expand_more'}
          </span>
        </button>

        {/* Quick clear filter button */}
        {hasActiveFilter && (
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              handlePresetAll();
            }}
            className="p-1 mr-1 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 rounded-md hover:bg-slate-200/50 dark:hover:bg-slate-700 transition-colors cursor-pointer"
            title="Clear date filter"
            aria-label="Clear date filter"
          >
            <span className="material-symbols-outlined text-[14px]">close</span>
          </button>
        )}
      </div>

      {/* CALENDAR POPOVER MODAL */}
      {isOpen && (
        <div
          className="absolute right-0 mt-2 z-50 w-80 sm:w-88 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl shadow-2xl p-4 flex flex-col gap-3.5 text-xs font-sans animate-in fade-in zoom-in-95 duration-100 select-none"
          role="dialog"
          aria-label="Calendar date range picker"
        >

          {/* MONTH & YEAR HEADER NAVIGATION */}
          <div className="flex items-center justify-between gap-2 px-1">
            <button
              type="button"
              onClick={handlePrevMonth}
              className="p-1 rounded-lg text-slate-500 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer"
              title="Previous month"
            >
              <span className="material-symbols-outlined text-[18px]">chevron_left</span>
            </button>

            <div className="flex items-center gap-1.5">
              <span className="text-xs font-bold text-slate-900 dark:text-white">
                {MONTH_NAMES[viewMonth]} {viewYear}
              </span>
              <button
                type="button"
                onClick={handleJumpToday}
                className="text-[10px] font-medium text-[#006591] dark:text-sky-400 hover:underline cursor-pointer"
                title="Jump to current month"
              >
                Today
              </button>
            </div>

            <button
              type="button"
              onClick={handleNextMonth}
              className="p-1 rounded-lg text-slate-500 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer"
              title="Next month"
            >
              <span className="material-symbols-outlined text-[18px]">chevron_right</span>
            </button>
          </div>

          {/* WEEKDAYS HEADER */}
          <div className="grid grid-cols-7 gap-1 text-center">
            {WEEK_DAYS.map((wd) => (
              <div
                key={wd}
                className="text-[10px] font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500 py-0.5"
              >
                {wd}
              </div>
            ))}
          </div>

          {/* CALENDAR DAYS GRID */}
          <div className="grid grid-cols-7 gap-1">
            {calendarDays.map((day) => {
              const isStart = day.key === activeStart;
              const isEnd = day.key === activeEnd;
              const isSingleSelected = isStart && (activeStart === activeEnd);

              const isInRange = Boolean(
                tentativeStart &&
                activeEnd &&
                day.key > tentativeStart &&
                day.key < activeEnd
              );

              const hasCaptures = availableDateSet.has(day.key);
              const isToday = day.key === formatDateKey(new Date());

              let cellStyle = 'text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800';

              if (!day.isCurrentMonth) {
                cellStyle = 'text-slate-300 dark:text-slate-600 hover:bg-slate-50 dark:hover:bg-slate-800/50';
              }

              if (isSingleSelected) {
                cellStyle = 'bg-[#006591] dark:bg-sky-600 text-white font-bold rounded-lg shadow-2xs';
              } else if (isStart) {
                cellStyle = 'bg-[#006591] dark:bg-sky-600 text-white font-bold rounded-l-lg shadow-2xs';
              } else if (isEnd) {
                cellStyle = 'bg-[#006591] dark:bg-sky-600 text-white font-bold rounded-r-lg shadow-2xs';
              } else if (isInRange) {
                cellStyle = 'bg-sky-50 dark:bg-sky-950/60 text-[#006591] dark:text-sky-300 font-semibold rounded-none';
              }

              return (
                <button
                  key={day.key}
                  type="button"
                  onClick={() => handleDayClick(day.key)}
                  onMouseEnter={() => {
                    if (isPickingEnd) setHoverDate(day.key);
                  }}
                  className={`h-8 flex flex-col items-center justify-center relative transition-all duration-75 text-xs font-sans cursor-pointer ${cellStyle}`}
                  title={`${day.key}${hasCaptures ? ' (Captures available)' : ''}`}
                >
                  <span className="leading-none">{day.dayNum}</span>

                  {/* Indicator dot for captures on this date */}
                  {hasCaptures && !isStart && !isEnd && (
                    <span className="w-1 h-1 rounded-full bg-sky-500 dark:bg-sky-400 absolute bottom-1"></span>
                  )}
                  {hasCaptures && (isStart || isEnd) && (
                    <span className="w-1 h-1 rounded-full bg-white absolute bottom-1"></span>
                  )}

                  {/* Subtle ring for today if unselected */}
                  {isToday && !isStart && !isEnd && !isInRange && (
                    <span className="absolute inset-0.5 rounded-md border border-[#006591]/40 dark:border-sky-400/50 pointer-events-none"></span>
                  )}
                </button>
              );
            })}
          </div>

          {/* MANUAL START & END DATE INPUT FIELDS */}
          <div className="flex items-center gap-2 pt-2 border-t border-slate-100 dark:border-slate-800">
            <div className="flex-1 flex flex-col gap-1">
              <label className="text-[10px] font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">
                Start Date
              </label>
              <input
                type="date"
                value={selectionStart || ''}
                onChange={(e) => handleManualDateChange('start', e.target.value)}
                className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-800 dark:text-slate-200 text-xs rounded-md px-2 py-1 focus:outline-none focus:ring-1 focus:ring-[#006591] dark:focus:ring-sky-500"
              />
            </div>
            <span className="text-slate-400 self-end pb-1.5">→</span>
            <div className="flex-1 flex flex-col gap-1">
              <label className="text-[10px] font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">
                End Date
              </label>
              <input
                type="date"
                value={selectionEnd || ''}
                onChange={(e) => handleManualDateChange('end', e.target.value)}
                className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-800 dark:text-slate-200 text-xs rounded-md px-2 py-1 focus:outline-none focus:ring-1 focus:ring-[#006591] dark:focus:ring-sky-500"
              />
            </div>
          </div>

          {/* VALIDATION ERROR DISPLAY */}
          {validationError && (
            <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-rose-50 dark:bg-rose-950/40 text-rose-600 dark:text-rose-400 border border-rose-200 dark:border-rose-800 text-[11px] font-medium animate-in fade-in duration-150">
              <span className="material-symbols-outlined text-[14px] shrink-0">error</span>
              <span>{validationError}</span>
            </div>
          )}

          {/* POPOVER FOOTER */}
          <div className="flex items-center justify-between gap-2 pt-1">
            <div className="text-[11px] text-slate-500 dark:text-slate-400 truncate">
              {validationError ? (
                <span className="text-rose-500 font-medium">Fix invalid dates</span>
              ) : isPickingEnd ? (
                <span className="text-[#006591] dark:text-sky-400 font-medium">Click end date to finish</span>
              ) : (
                <span>
                  {hasActiveFilter ? 'Filter active' : 'Showing all captures'}
                </span>
              )}
            </div>

            <div className="flex items-center gap-1.5">
              <button
                type="button"
                onClick={handlePresetAll}
                className="px-2.5 py-1 text-[11px] font-medium text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors cursor-pointer"
              >
                Reset
              </button>
              <button
                type="button"
                onClick={() => {
                  if (selectionStart && selectionEnd && selectionStart > selectionEnd) {
                    setValidationError('Start date cannot be after End date');
                    return;
                  }
                  setValidationError(null);
                  setIsOpen(false);
                  setIsPickingEnd(false);
                  if (onChange && (selectionStart || selectionEnd)) {
                    onChange({
                      startDate: selectionStart || selectionEnd,
                      endDate: selectionEnd || selectionStart,
                      isCustom: true
                    });
                  }
                }}
                disabled={Boolean(validationError)}
                className={`px-3 py-1 rounded-lg text-[11px] font-semibold transition-colors cursor-pointer ${
                  validationError
                    ? 'bg-slate-200 dark:bg-slate-700 text-slate-400 cursor-not-allowed'
                    : 'bg-[#006591] hover:bg-[#00557a] dark:bg-sky-600 dark:hover:bg-sky-500 text-white shadow-2xs'
                }`}
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
