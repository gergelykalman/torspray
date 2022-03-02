import curses


class TUI:
    def __init__(self):
        self.stdscr = None
        self.lines = 1

    def __getmax(self):
        y, x = self.stdscr.getmaxyx()
        return x, y

    def __printat(self, x, y, line):
        self.stdscr.addstr(y, x, line)

    def start(self):
        self.stdscr = curses.initscr()
        curses.start_color()
        self.stdscr.nodelay(True)
        self.stdscr.keypad(True)

    def stop(self):
        curses.endwin()

    def resetlines(self):
        self.lines = 1
        self.stdscr.border()

    def clear(self):
        self.stdscr.clear()

    def getch(self):
        keycode = self.stdscr.getch()
        if keycode == -1:
            pass
        else:
            c = chr(keycode)
            self.print("{} {} {}".format(c, keycode, type(keycode)))
            if c in ("Q", "q"):
                raise KeyboardInterrupt

    def print(self, line=""):
        self.__printat(1, self.lines, line)
        self.lines += 1

    def refresh(self):
        self.stdscr.refresh()

    def print_header(self):
        self.__printat(1, self.lines,
                       "hostname                        RX                   TX               total RX             total TX")
        self.lines += 1

    def print_bandwidth(self, name, diff_rx, diff_tx, total_rx, total_tx):
        self.__printat(1, self.lines, "{}           {:10.2f} Mbit/s       {:10.2f} Mbit/s     {:10.2f} GB         {:10.2f} GB".format(name, diff_rx,
                                                                                                         diff_tx,
                                                                                                         total_rx,
                                                                                                         total_tx))
        self.lines += 1

    def print_footer(self, now, delta, sleeptime, all_diff_rx, all_diff_tx, all_rx, all_tx):
        self.__printat(1, self.lines, "TOTAL:               {:10.2f} Mbit/s       {:10.2f} Mbit/s     {:10.2f} GB         {:10.2f} GB".format(all_diff_rx, all_diff_tx, all_rx, all_tx))
        self.lines += 1

        x, y = self.__getmax()
        self.__printat(1, y-2, "{}   delta: {:.2f}, sleeptime: {:.2f}".format(
            now, delta, sleeptime
        ))
