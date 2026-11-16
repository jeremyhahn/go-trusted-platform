import { configure } from "@testing-library/react";

// Testing Library's async queries (findBy*, waitFor) give up after 1000 ms by
// default. Under CI load the first render of a page in a test file is cold
// (module transforms, first React commit) and can take longer than that: main
// d7ec2b8e1, push run 43678372512, failed "selects the first bucket and lists
// its objects" in storage/objects/page.test.tsx after 2716 ms waiting for its
// first row. 5000 ms gives the cold render room and stays under vitest's
// 10000 ms testTimeout, so an element that never renders still fails with
// Testing Library's "Unable to find an element" message, not a test timeout.
configure({ asyncUtilTimeout: 5000 });
