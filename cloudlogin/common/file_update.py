import re
import os
import logging

logger = logging.getLogger("cloudlogin")
logger.addHandler(logging.NullHandler())


def update_values_in_file(file_path, updates):
    if not os.path.exists(file_path):
        raise FileExistsError(f"File not found at {file_path}")

    try:
        with open(file_path, 'r') as file:
            content = file.read()

            for item, data in updates.items():
                value_to_set = data['value']
                aliases = data['aliases']
                key_found_and_updated = False

                for alias in aliases:
                    escaped_alias = re.escape(alias)
                    pattern = re.compile(r'^(%s\s*=\s*").*(")' % escaped_alias, re.MULTILINE)

                    content, num_subs = re.subn(pattern, f'\\1{value_to_set}\\2', content)

                    if num_subs > 0:
                        logger.info(f"Updated {alias}")
                        key_found_and_updated = True
                        break

                if not key_found_and_updated:
                    raise KeyError(f"No key for {item} was found in the file.")

        with open(file_path, 'w') as file:
            file.write(content)

        logger.debug(f"File update finished for {file_path}")

    except Exception as e:
        raise RuntimeError(f"Error: {e}")
