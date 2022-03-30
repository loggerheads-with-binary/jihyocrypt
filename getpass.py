import sys, os
import enum

"""Just checking differences"""

class SPECIAL_MASKS(enum.Enum):

	NO_MASK = False
	BLIND_MASK = None
	DEFAULT_MASK = "*"
	ONE_REVERSE = 0xfff
	MIMI_REVERSE = 0x1ff

##GP_DEFAULT_MASK = SPECIAL_MASKS.get(os.environ.get("GETPASS_MASK" , None) , "DEFAULT_MASK")
GP_DEFAULT_MASK = getattr(SPECIAL_MASKS , os.environ.get("GETPASS_MASK" , '')  , SPECIAL_MASKS.DEFAULT_MASK  )
class OneReverse():

	def __init__(self, colored , colorset):

		if colored:
			import termcolor
			self.colored = lambda x : termcolor.colored(x , colorset[-1])

		else :
			self.colored = lambda x : x

	def mask(self):
		global password

		if len(password) == 1 :
			return self.colored(password[0])


		return self.colored(f'\b{SPECIAL_MASKS.DEFAULT_MASK.value}{password[-1]}')

	def blank(self):

		return '\b \b'

	def enter(self):
		return self.colored(f'\b{SPECIAL_MASKS.DEFAULT_MASK.value}\n')
		pass

class MimiReverse(OneReverse):

	def blank(self):

		global password

		if len(password) == 1 :
			return '\b \b'

		return self.colored(f'\b\b{password[-2]} \b')

standardize_to_str = lambda x : x if (isinstance(x , str)) else ((x.decode('utf8')) if isinstance(x , bytes) else str(x))

password = ""

class _Getch:
    """Gets a single character from standard input.  Does not echo to the
	screen."""
    def __init__(self):
        try:
            self.impl = _GetchWindows()
        except ImportError:
            self.impl = _GetchUnix()

    def __call__(self): return self.impl()

class _GetchUnix:
    def __init__(self):
        import tty, sys

    def __call__(self):
        import sys, tty, termios
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(sys.stdin.fileno())
            ch = sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        return ch

class _GetchWindows:
    def __init__(self):
        import msvcrt

    def __call__(self):
        import msvcrt
        return msvcrt.getch()

getch = _Getch()

def getpass(	prompt : str = "Enter Password: " , mask : str = GP_DEFAULT_MASK ,
				colored : bool = False , colorset : list = None ,
				stdin = sys.stdin , stdout = sys.stderr ,
				on_error : bool = True):

	global password
	password = '' 							##Refreshing to make sure last remnants dont remain

	if stdin != sys.stdin :
		raise AttributeError(f'It is an old attribute. Now by default stdin has to be sys.stdin')

	def printex(content ):
		nonlocal stdout


	if colored:
		if colorset is None:
			colorset = ['yellow' , 'green']

	if (mask == None) or (mask == '') or (mask == b'') or (mask == SPECIAL_MASKS.BLIND_MASK):
		mask = lambda : ''
		blank = lambda  : ''
		enter = lambda : '\n'

	elif (mask == True)  or (mask == SPECIAL_MASKS.DEFAULT_MASK):

		if colored:
			mask = lambda : termcolor.colored(SPECIAL_MASKS.DEFAULT_MASK.value , colorset[-1])
			import termcolor
			blank = lambda : '\b \b'
			enter = lambda : '\n'


		else :
			mask = lambda : SPECIAL_MASKS.DEFAULT_MASK.value
			blank = lambda : '\b \b'
			enter = lambda : '\n'

	elif (mask == False ) or (mask == SPECIAL_MASKS.NO_MASK):

		if colored:

			import termcolor

			def masker(x = None):       #Param x just to avoid pre-computation of lambda
				global password
				nonlocal colorset
				return termcolor.colored(password[-1] , colorset[-1])

			mask = lambda : masker(None)
			blank = lambda : '\b \b'
			enter = lambda : '\n'

		else :

			def masker(x = None):       #Param x just to avoid pre-computation of lambda
				global password
				return password[-1]

			mask = lambda : masker(None)
			blank = lambda : '\b \b'
			enter = lambda : '\n'

	elif (mask == SPECIAL_MASKS.ONE_REVERSE):

		one_reverse = OneReverse(colored , colorset)

		mask = one_reverse.mask
		blank = one_reverse.blank
		enter = one_reverse.enter

	elif (mask == SPECIAL_MASKS.MIMI_REVERSE):

		mimi_reverse = MimiReverse(colored , colorset)

		mask = mimi_reverse.mask
		blank = mimi_reverse.blank
		enter = mimi_reverse.enter

	else :

		mask_ = str(mask)[0]

		if colored:
			import termcolor
			mask_ = termcolor.colored(mask_ , colorset[-1])
			mask = lambda : mask_

		else:
			mask = lambda : mask_

		blank = lambda : '\b \b'
		enter = lambda : '\n'

	if colored:
		import termcolor
		termcolor.cprint(prompt , color = colorset[0] , end = '' , file = stdout)
		stdout.flush()
	else:
		print(prompt , end = '' , file = stdout)
		stdout.flush()

	while True :

		try:
			character = standardize_to_str(getch.__call__())
			key = ord(character)

		except:
			continue

		if key == 13:


			stdout.write(enter())
			stdout.flush()
			return password

		elif key == 27 :
			#Escape Kye
			continue

		elif key in (8,127):

				if len(password) > 0:

					stdout.write(blank())
					stdout.flush()

					password = password[:-1]


		elif key == 3 : #Ctrl C

			if on_error:
				raise KeyboardInterrupt(f'Password Input has been interrupted by user')

			return None

		elif -1 < key < 32 :
			continue


		else :

			password += character
			stdout.write(mask())
			stdout.flush()
