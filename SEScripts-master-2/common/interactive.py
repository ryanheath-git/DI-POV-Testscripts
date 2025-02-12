import re
import pathlib


def format_input_prompt(prompt, default, indent_level: int = None):
    if indent_level is not None:
        prompt = ('\t' * indent_level) + prompt
    if default is not None:
        prompt = f'{prompt} (default: {default})'
    return f'{prompt}: '


def error_prompt(prompt: str, indent_level: int = None):
    if indent_level is not None:
        prompt = ('\t' * indent_level) + prompt
    print(f'{prompt}')


def warning_prompt(prompt: str, indent_level: int = None):
    if indent_level is not None:
        prompt = ('\t' * indent_level) + prompt
    print(f'{prompt}')


def msg(prompt: str, indent_level: int = None):
    if indent_level is not None:
        prompt = ('\t' * indent_level) + prompt
    print(f'{prompt}')


def render_numbered_list(choices, default, indent_level, render_flat):
    i = 0
    newline_ct = 0
    numerical_default = 0
    selection_list_indent_level = indent_level + 1
    for choice in choices:
        if render_flat:
            if newline_ct == 0:
                print('\t' * selection_list_indent_level, end='')
            if newline_ct == 8:
                print('')
                print('\t' * selection_list_indent_level, end='')
                newline_ct = 0
            print(f'{i}.{choice}', end=' ')
            newline_ct += 1
        else:
            print('\t' * selection_list_indent_level, end='')
            print(f'{i}. {choice}')
        if choice == default:
            numerical_default = i
        i += 1
    return numerical_default


def input_filepath(prompt: str, default: str = '.', str_format: str = None, indent_level: int = None):
    prompt = format_input_prompt(prompt, default, indent_level)
    value = ""
    while True:
        value = input(prompt) or default
        if str_format is not None:
            match = re.match(str_format, value)
            if not match:
                print(f'Please enter a value matching the format {str_format}')
                continue

        if not pathlib.Path(value).is_dir():
            msg(f'Filepath [{value}] does not exist. Creating...', indent_level=1)
            pathlib.Path(value).mkdir(parents=True)

        return value


def input_int(prompt: str, default: int = None, min_: int = None, max_: int = None, indent_level: int = 0):
    prompt = format_input_prompt(prompt, default, indent_level)
    while True:
        try:
            value = input(prompt) or default
            value = int(value)
        except ValueError:
            print(f'Please enter a number between {min} and {max} ')
            continue

        if min_ is not None and value < min_:
            print(f'Please enter a number greater than or equal to {min_}')
            continue
        elif max_ is not None and value > max_:
            print(f'Please enter a number less than or equal to {max_}')
            continue
        else:
            return value


def input_selection(prompt: str, choices: [], default: str = None, numbered: bool = True, render_flat: bool = False,
                    indent_level: int = 0):
    '''
    Input from a selection in a list
    @param prompt: user prompt for input
    @param default: the default choice
    @param choices: list choices
    @param numbered: True, renders numbered list
    @param render_flat: renders the list in rows and columns to conserve space
    @param indent_level: number of indents to render input prompt and user selections
    @return:
    '''
    prompt = format_input_prompt(prompt, None, indent_level=indent_level)
    print(prompt)

    numerical_default = render_numbered_list(choices, default, indent_level, render_flat)

    print('')
    value = input_int('Selection', numerical_default, min_=0, max_=len(choices), indent_level=indent_level + 1)
    return choices[value]


def input_selection_or_string(prompt: str, choices: [], default: str = None, numbered: bool = True,
                              render_flat: bool = False,
                              indent_level: int = 0):
    '''
    Input can be either a selection from a list or a string of any format
    @param prompt: user prompt for input
    @param default: the default choice
    @param choices: list choices
    @param numbered: True, renders numbered list
    @param render_flat: renders the list in rows and columns to conserve space
    @param indent_level: number of indents to render input prompt and user selections
    @return:
    '''
    prompt = format_input_prompt(prompt, default, indent_level)
    print(prompt)

    numerical_default = render_numbered_list(choices, default, indent_level, render_flat)

    print('')
    while True:
        value = input_string('Selection', str(numerical_default), indent_level=indent_level + 1)
        if value.isdigit():
            value = int(value)
            if value > len(choices) - 1:
                print(error_prompt('Invalid selection'))
                continue
            else:
                return choices[value]
        else:
            return value


def input_string(prompt: str, default: str = None, str_format: str = None, indent_level: int = None):
    prompt = format_input_prompt(prompt, default, indent_level)
    value = ""
    while True:
        value = input(prompt) or default
        if str_format is not None:
            match = re.match(str_format, value)
            if not match:
                print(f'Please enter a value matching the format {str_format}')
                continue

        return value


def input_yes_no(prompt: str, default: str, indent_level: int = None):
    prompt = format_input_prompt(prompt, default, indent_level)
    expr = "yes|y|no|n"
    while True:
        value = input(prompt) or default
        if re.match(expr, value, re.IGNORECASE):
            if value == 'y':
                value = 'yes'
            elif value == 'n':
                value = 'no'
            return True if value == 'yes' else False
        print(f'Please enter a value matching the regular expression {expr}')
