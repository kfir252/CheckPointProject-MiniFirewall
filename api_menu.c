#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PROC_API_PATH "/proc/firewall_api"
#define PORTLIST_FILENAME "/etc/portlist.txt"
#define BLACKLIST_FILENAME "/etc/blacklist.txt"

void view_file(const char *filename)
{
    FILE *file;
    char line[256];

    file = fopen(filename, "r");
    if (file == NULL)
    {
        perror("Error opening file");
        return;
    }

    printf("\nContents of %s:\n", filename);
    while (fgets(line, sizeof(line), file))
    {
        printf("%s", line);
    }
    fclose(file);
    printf("\nPress Enter to continue...");
    getchar();
}

// Function to add a new entry to a file (for ports or DNS)
void add_entry_to_file(const char *filename, const char *entry)
{
    FILE *file = fopen(filename, "a");
    if (file == NULL)
    {
        perror("Error opening file for appending");
        return;
    }
    fprintf(file, "%s\n", entry);
    fclose(file);
    printf("Added '%s' to %s.\n", entry, filename);
}

// Function to remove an entry from a file (for ports or DNS)
void remove_entry_from_file(const char *filename, const char *entry)
{
    FILE *file = fopen(filename, "r");
    FILE *temp_file = fopen("data/temp.txt", "w");
    char line[256];
    bool found = false;

    if (file == NULL || temp_file == NULL)
    {
        perror("Error opening file for removal");
        if (file)
            fclose(file);
        if (temp_file)
            fclose(temp_file);
        return;
    }

    // Copy lines except the one to be removed
    while (fgets(line, sizeof(line), file))
    {
        // Remove newline for comparison
        line[strcspn(line, "\n")] = 0;
        if (strcmp(line, entry) != 0)
        {
            fprintf(temp_file, "%s\n", line);
        }
        else
        {
            found = true;
        }
    }

    fclose(file);
    fclose(temp_file);

    if (found)
    {
        // Replace the original file with the temp file
        rename("data/temp.txt", filename);
        printf("Removed '%s' from %s.\n", entry, filename);
    }
    else
    {
        printf("'%s' not found in %s.\n", entry, filename);
        remove("data/temp.txt"); // Delete temp file if not found
    }
}

// Menu for Sniffing Configuration Tools
void sniffing_tools_menu()
{
    char choice;
    char port[16];
    bool run = true;

    while (run)
    {
        system("clear");
        print_sniffing_tools_menu();
        printf("Enter your choice: ");
        choice = getchar();
        getchar(); // Clear newline from input buffer

        switch (choice)
        {
        case '1':
            // View the current ports list from portlist.txt
            view_file(PORTLIST_FILENAME);
            break;
        case '2':
            // Add a new port to the portlist
            printf("Enter port to add: ");
            fgets(port, sizeof(port), stdin);
            port[strcspn(port, "\n")] = 0; // Remove newline
            add_entry_to_file(PORTLIST_FILENAME, port);
            break;
        case '3':
            // Remove a port from the portlist
            printf("Enter port to remove: ");
            fgets(port, sizeof(port), stdin);
            port[strcspn(port, "\n")] = 0; // Remove newline
            remove_entry_from_file(PORTLIST_FILENAME, port);
            break;
        case 'x':
        case 'X':
            run = false;
            break;
        default:
            printf("Invalid choice, please try again.\n");
        }
    }
}

// Menu for Blocker Configuration Tools
void blocker_tools_menu()
{
    char choice;
    char dns[256];
    bool run = true;

    while (run)
    {
        system("clear");
        print_blocker_tools_menu();
        printf("Enter your choice: ");
        choice = getchar();
        getchar(); // Clear newline from input buffer

        switch (choice)
        {
        case '1':
            // View the blacklist from blacklist.txt
            view_file(BLACKLIST_FILENAME);
            break;
        case '2':
            // Add a new DNS to the blacklist
            printf("Enter DNS to add to blacklist: ");
            fgets(dns, sizeof(dns), stdin);
            dns[strcspn(dns, "\n")] = 0; // Remove newline
            add_entry_to_file(BLACKLIST_FILENAME, dns);
            break;
        case '3':
            // Remove a DNS from the blacklist
            printf("Enter DNS to remove from blacklist: ");
            fgets(dns, sizeof(dns), stdin);
            dns[strcspn(dns, "\n")] = 0; // Remove newline
            remove_entry_from_file(BLACKLIST_FILENAME, dns);
            break;
        case 'x':
        case 'X':
            run = false;
            break;
        default:
            printf("Invalid choice, please try again.\n");
        }
    }
}

// Main menu
void print_main_menu()
{
    system("clear");
    printf("+----------------------------------------+\n");
    printf("|     Mini Firewall API - Main Menu      |\n");
    printf("+-----+----------------------------------+\n");
    printf("| [1] | Sniffing Configuration Tools     |\n");
    printf("| [2] | Blocker Configuration Tools      |\n");
    printf("|     |                                  |\n");
    printf("| [X] | Exit                             |\n");
    printf("+-----+----------------------------------+\n");
}

void print_sniffing_tools_menu()
{
    system("clear"); // Clear console
    printf("+----------------------------------+\n");
    printf("|   Sniffing Configuration Tools   |\n");
    printf("+-----+----------------------------+\n");
    printf("| [1] | View Current Ports List    |\n");
    printf("| [2] | Add Port                   |\n");
    printf("| [3] | Remove Port                |\n");
    printf("|     |                            |\n");
    printf("| [X] | Back                       |\n");
    printf("+-----+----------------------------+\n");
}

void print_blocker_tools_menu()
{
    system("clear"); // Clear console
    printf("+-----------------------------------+\n");
    printf("|    Blocker Configuration Tools    |\n");
    printf("+-----+-----------------------------+\n");
    printf("| [1] | View Current Ports List     |\n");
    printf("| [2] | Add Port                    |\n");
    printf("| [3] | Remove Port                 |\n");
    printf("|     |                             |\n");
    printf("| [X] | Back                        |\n");
    printf("+-----+-----------------------------+\n");
}
int main()
{
    char choice;
    bool run = true;

    while (run)
    {
        print_main_menu();
        printf("Enter your choice: ");
        choice = getchar();
        getchar(); // Clear newline from input buffer

        switch (choice)
        {
        case '1':
            sniffing_tools_menu();
            break;
        case '2':
            blocker_tools_menu();
            break;
        case 'x':
        case 'X':
            printf("Exiting...\n");
            run = false;
            break;
        default:
            printf("Invalid choice, please try again.\n");
        }
    }

    return 0;
}