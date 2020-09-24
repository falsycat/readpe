add_executable(readpe
    args.c
    main.c
    output.c
)
target_link_libraries(readpe
    parsarg-c
)
