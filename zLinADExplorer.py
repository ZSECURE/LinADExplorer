#!/usr/bin/python3
import argparse
from ldap3 import Server, Connection, ALL, Tls
import ssl
import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext
import getpass
from PIL import Image, ImageTk

def query_ldap(server_address, username, password, search_base, search_filter, attributes, use_ldaps):
    if use_ldaps:
        # Configure TLS for LDAPS
        tls_configuration = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
        server = Server(server_address, use_ssl=True, tls=tls_configuration, get_info=ALL)
    else:
        server = Server(server_address, get_info=ALL)

    conn = Connection(server, user=username, password=password, auto_bind=True)
    conn.search(search_base, search_filter, attributes=attributes)
    return conn.entries

def build_tree(parent, entries, tree, object_type):
    for entry in entries:
        dn = entry.entry_dn
        cn = entry.cn.value if 'cn' in entry else 'Unknown'
        object_class = entry['objectClass'].value if 'objectClass' in entry else []
        sam_account_name = entry['sAMAccountName'].value if 'sAMAccountName' in entry else ''

        if object_type in object_class:
            # Skip entries with sAMAccountName ending with '$' for user objects
            if 'user' in object_type and sam_account_name.endswith('$'):
                continue

            # Determine icon based on object type
            if 'computer' in object_type:
                icon = tree.computer_icon
            elif 'group' in object_type:
                icon = tree.group_icon
            else:
                icon = tree.user_icon

            node = tree.insert(parent, 'end', text=cn, open=True, image=icon, values=(dn,))
            child_entries = [e for e in entries if e.entry_dn.endswith(',' + dn)]
            build_tree(node, child_entries, tree, object_type)

def filter_tree(tree, search_text, object_type):
    for item in tree.get_children():
        tree.delete(item)
    for entry in tree.entries:
        cn = entry.cn.value if 'cn' in entry else 'Unknown'
        if search_text.lower() in cn.lower():
            # Determine icon based on object type
            if 'computer' in object_type:
                icon = tree.computer_icon
            elif 'group' in object_type:
                icon = tree.group_icon
            else:
                icon = tree.user_icon

            tree.insert('', 'end', text=cn, values=(entry.entry_dn,), image=icon)

def create_gui(entries):
    root = tk.Tk()
    root.title("LDAP Directory Structure")
    root.geometry("1200x700")

    # Create a PanedWindow
    paned_window = ttk.PanedWindow(root, orient=tk.HORIZONTAL)
    paned_window.pack(fill=tk.BOTH, expand=True)

    # Create the notebook for the left pane
    left_notebook = ttk.Notebook(paned_window)
    left_notebook.pack(expand=True, fill='both')

    # Tabs for users, groups, and computers
    user_tab = ttk.Frame(left_notebook)
    group_tab = ttk.Frame(left_notebook)
    computer_tab = ttk.Frame(left_notebook)

    left_notebook.add(user_tab, text='Users')
    left_notebook.add(group_tab, text='Groups')
    left_notebook.add(computer_tab, text='Computers')

    # Create treeviews for each tab
    user_tree = ttk.Treeview(user_tab, columns=("DN",), show="tree")
    group_tree = ttk.Treeview(group_tab, columns=("DN",), show="tree")
    computer_tree = ttk.Treeview(computer_tab, columns=("DN",), show="tree")

    user_tree.pack(expand=True, fill='both')
    group_tree.pack(expand=True, fill='both')
    computer_tree.pack(expand=True, fill='both')

    # Load and assign icons to each specific tree
    user_tree.user_icon = ImageTk.PhotoImage(Image.open("user_icon.png").resize((16, 16)))
    group_tree.group_icon = ImageTk.PhotoImage(Image.open("group_icon.png").resize((16, 16)))
    computer_tree.computer_icon = ImageTk.PhotoImage(Image.open("computer_icon.png").resize((16, 16)))

    # Assign a default icon for any unspecified cases
    default_icon = ImageTk.PhotoImage(Image.open("default_icon.png").resize((16, 16)))
    user_tree.default_icon = default_icon
    group_tree.default_icon = default_icon
    computer_tree.default_icon = default_icon

    # Store entries in each tree for filtering
    user_tree.entries = [e for e in entries if 'user' in e['objectClass'].value and not e['sAMAccountName'].value.endswith('$')]
    group_tree.entries = [e for e in entries if 'group' in e['objectClass'].value]
    computer_tree.entries = [e for e in entries if 'computer' in e['objectClass'].value]

    # Build the trees
    build_tree('', user_tree.entries, user_tree, 'user')
    build_tree('', group_tree.entries, group_tree, 'group')
    build_tree('', computer_tree.entries, computer_tree, 'computer')

    # Create search entry and label
    search_label = ttk.Label(root, text="Search:")
    search_label.pack(side=tk.TOP, fill=tk.X)
    search_entry = ttk.Entry(root)
    search_entry.pack(side=tk.TOP, fill=tk.X)

    def on_search(event):
        current_tab = left_notebook.index(left_notebook.select())
        if current_tab == 0:  # Users tab
            filter_tree(user_tree, search_entry.get(), 'user')
        elif current_tab == 1:  # Groups tab
            filter_tree(group_tree, search_entry.get(), 'group')
        elif current_tab == 2:  # Computers tab
            filter_tree(computer_tree, search_entry.get(), 'computer')

    # Bind search entry to filter function
    search_entry.bind("<KeyRelease>", on_search)

    # Create the detail frame with tabs
    detail_frame = ttk.Frame(paned_window, padding=(10, 10))
    right_notebook = ttk.Notebook(detail_frame)
    right_notebook.pack(expand=True, fill='both')

    tabs = {
        'all': ttk.Frame(right_notebook),
        'user': ttk.Frame(right_notebook),
        'group': ttk.Frame(right_notebook),
        'computer': ttk.Frame(right_notebook)
    }

    for tab_name, tab_frame in tabs.items():
        right_notebook.add(tab_frame, text=tab_name.capitalize())

        # Add a scrolled text widget to each tab for better text management
        scrolled_text = scrolledtext.ScrolledText(tab_frame, wrap=tk.WORD)
        scrolled_text.pack(expand=True, fill='both')
        tabs[tab_name] = scrolled_text  # Store the ScrolledText widget directly

    # Add frames to the paned window
    paned_window.add(left_notebook, weight=1)
    paned_window.add(detail_frame, weight=3)

    # Bind the tree selection event
    user_tree.bind('<<TreeviewSelect>>', lambda e: on_tree_select(e, user_tree, tabs, entries))
    group_tree.bind('<<TreeviewSelect>>', lambda e: on_tree_select(e, group_tree, tabs, entries))
    computer_tree.bind('<<TreeviewSelect>>', lambda e: on_tree_select(e, computer_tree, tabs, entries))

    root.mainloop()

def on_tree_select(event, tree, tabs, entries):
    selected_item = tree.selection()
    if selected_item:
        item = tree.item(selected_item)
        dn = item['values'][0]  # DN is stored in the first value

        # Clear previous details
        for scrolled_text in tabs.values():
            scrolled_text.delete('1.0', tk.END)

        # Find the entry
        entry = next((e for e in entries if e.entry_dn == dn), None)
        if entry:
            object_class = entry['objectClass'].value if 'objectClass' in entry else []

            # Define attributes for each type
            all_attributes = entry.entry_attributes_as_dict.keys()
            user_attributes = [
                "cn", "sn", "givenName", "distinguishedName", "sAMAccountName",
                "userPrincipalName", "mail", "memberOf", "objectClass",
                "objectGUID", "objectSid", "description", "telephoneNumber",
                "title", "department", "company", "manager", "member",
                "pwdLastSet", "accountExpires", "userAccountControl",
                "whenCreated", "whenChanged", "lastLogonTimestamp", "logonCount"
            ]

            group_attributes = [
                "cn", "distinguishedName", "sAMAccountName", "objectClass",
                "objectGUID", "description", "member", "memberOf",
                "groupType", "whenCreated", "whenChanged", "managedBy"
            ]

            computer_attributes = [
                "cn", "distinguishedName", "sAMAccountName", "objectClass",
                "objectGUID", "description", "operatingSystem",
                "operatingSystemVersion", "operatingSystemServicePack",
                "dNSHostName", "userAccountControl", "whenCreated",
                "whenChanged", "lastLogonTimestamp", "memberOf"
            ]

            # Display all attributes
            scrolled_text = tabs['all']
            for attr in all_attributes:
                value = entry[attr].value if attr in entry else 'N/A'
                scrolled_text.insert(tk.END, f"{attr}: {value}\n")

            # Display user attributes
            if 'user' in object_class and not 'computer' in object_class:
                scrolled_text = tabs['user']
                for attr in user_attributes:
                    value = entry[attr].value if attr in entry else 'N/A'
                    scrolled_text.insert(tk.END, f"{attr}: {value}\n")

            # Display group attributes
            if 'group' in object_class:
                scrolled_text = tabs['group']
                for attr in group_attributes:
                    value = entry[attr].value if attr in entry else 'N/A'
                    scrolled_text.insert(tk.END, f"{attr}: {value}\n")

            # Display computer attributes
            if 'computer' in object_class:
                scrolled_text = tabs['computer']
                for attr in computer_attributes:
                    value = entry[attr].value if attr in entry else 'N/A'
                    scrolled_text.insert(tk.END, f"{attr}: {value}\n")


def main():
    # Create a simple GUI to get connection details
    def connect():
        server = server_entry.get()
        username = username_entry.get()
        password = password_entry.get()
        base = base_entry.get()
        use_ldaps = use_ldaps_var.get()

        # Close the connection window
        connection_window.destroy()

        # Query LDAP and create the main GUI
        entries = query_ldap(server, username, password, base, '(|(objectClass=user)(objectClass=group)(objectClass=computer))', [
            "cn", "sn", "givenName", "distinguishedName", "sAMAccountName",
            "userPrincipalName", "mail", "memberOf", "objectClass",
            "objectGUID", "objectSid", "description", "telephoneNumber",
            "title", "department", "company", "manager", "member",
            "pwdLastSet", "accountExpires", "userAccountControl",
            "whenCreated", "whenChanged", "lastLogonTimestamp", "logonCount",
            "groupType", "managedBy", "operatingSystem", "operatingSystemVersion",
            "operatingSystemServicePack", "dNSHostName"
        ], use_ldaps)
        create_gui(entries)

    # Connection details window
    connection_window = tk.Tk()
    connection_window.title("LDAP Connection Details")
    connection_window.geometry("400x375")

    # Server address
    ttk.Label(connection_window, text="Server Address:").pack(pady=5)
    server_entry = ttk.Entry(connection_window)
    server_entry.pack(pady=5)
    server_entry.insert(0, 'ldap://your_domain_controller')

    # Username
    ttk.Label(connection_window, text="Username:").pack(pady=5)
    username_entry = ttk.Entry(connection_window)
    username_entry.pack(pady=5)
    username_entry.insert(0, 'your_username@domain')

    # Password
    ttk.Label(connection_window, text="Password:").pack(pady=5)
    password_entry = ttk.Entry(connection_window, show="*")
    password_entry.pack(pady=5)

    # Base DN
    ttk.Label(connection_window, text="Base DN:").pack(pady=5)
    base_entry = ttk.Entry(connection_window)
    base_entry.pack(pady=5)
    base_entry.insert(0, 'DC=your_domain,DC=com')

    # Use LDAPS
    use_ldaps_var = tk.BooleanVar()
    use_ldaps_check = ttk.Checkbutton(connection_window, text="Use LDAPS", variable=use_ldaps_var)
    use_ldaps_check.pack(pady=5)

    # Connect button
    connect_button = ttk.Button(connection_window, text="Connect", command=connect)
    connect_button.pack(pady=20)

    connection_window.mainloop()

if __name__ == "__main__":
    main()
