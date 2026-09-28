# Measured defect classes

Each class passed a Ready linter, was well-formed, and was false. Each row
named is where it was measured; read it for the full account.

| class                                               | measured on                      | the check that catches it                                |
| --------------------------------------------------- | -------------------------------- | -------------------------------------------------------- |
| false premise about the tree                        | CLOUD-1522                       | re-read each pointer at `origin/main`                    |
| a store's contents claimed from its writer's code   | CLOUD-1523                       | count the live instance                                  |
| a number with no reproducing command                | CLOUD-1522, CLOUD-1525           | re-run the command                                       |
| a gate named instead of a decision                  | CLOUD-1567                       | decide it, or leave the queue                            |
| a `tests` key filled from a glob                    | `rules/scanning.md` (2026-09-09) | a case that fails without the change                     |
| a mechanism undecided inside a valid block          | CLOUD-420                        | read §2 as a decision, not a shape                       |
| a prescription that breaks the row's own acceptance | CLOUD-858                        | test the prescription against §7                         |
| a filed blocker that was wrong                      | CLOUD-1865                       | resolve the blocker on the board                         |
| a refutation never written back to the row          | CLOUD-1194                       | search the board for the row's key                       |
| a parent's scope contradicting its child's          | CLOUD-1764                       | read parent and children together                        |
| a premise that expired after grooming               | CLOUD-1392, CLOUD-1717           | re-measure at promotion, not at filing                   |
| a mutation no sweep can reach                       | CLOUD-1526 clause 8              | where `batten mutate` looks vs where the row declared it |
| a grooming session drifting into landing            | CLOUD-1568                       | the board is the deliverable                             |
