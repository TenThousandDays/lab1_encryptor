#include <cstdlib>
#include <iostream>

int main(int argc, char* argv[])
{
    if (argc != 4) {
        std::cerr << "Usage:\n"
                  << "  " << argv[0] << " encrypt <directory_path> <password>\n"
                  << "  " << argv[0] << " decrypt <directory_path> <password>\n";
        return EXIT_FAILURE;
    }

    std::cout << "FolderProtector args ok\n";
    return EXIT_SUCCESS;
}
