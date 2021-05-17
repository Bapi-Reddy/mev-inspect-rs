use ethers::{abi::Abi, contract::BaseContract};
use crate::{
    types::{Inspection}
}

pub struct UniswapV3 {
    router: BaseContract,
    pool: BaseContract,
}

impl Inspector for UniswapV3 {
    fn inspect(&self, inspection: &mut Inspection) {
        let num_protocols = inspection.protocols.len();
        let actions = inspection.actions.to_vec();

        let mut prune: Vec<usize> = Vec::new();
        let mut has_trade = false;
        for i in 0..inspection.actions.len() {
            let action = &mut inspection.actions[i];

            if let Some(calltrace) = action.as_call() {
                let call = calltrace.as_ref();
                let preflight = self.is_preflight(call);

                // we classify AddLiquidity calls in order to find sandwich attacks
                // by removing/adding liquidity before/after a trade
                if let Ok((token0, token1, amount0, amount1, _, _, _, _)) = self
                    .router
                    .decode::<AddLiquidity, _>("addLiquidity", &call.input)
                {
                    let trace_address = calltrace.trace_address.clone();
                    *action = Classification::new(
                        AddLiquidityAct {
                            tokens: vec![token0, token1],
                            amounts: vec![amount0, amount1],
                        },
                        trace_address,
                    );
                } else if let Ok((_, _, _, bytes)) =
                    self.pool.decode::<PairSwap, _>("swap", &call.input)
                {
                    // add the protocol
                    let protocol = uniswappy(&call);
                    inspection.protocols.insert(protocol);

                    // skip flashswaps -- TODO: Get an example tx.
                    if !bytes.as_ref().is_empty() {
                        eprintln!("Flashswaps are not supported. {:?}", inspection.hash);
                        continue;
                    }

                    let res = find_matching(
                        // Iterate backwards
                        actions.iter().enumerate().rev().skip(actions.len() - i),
                        // Get a transfer
                        |t| t.transfer(),
                        // We just want the first transfer, no need to filter for anything
                        |_| true,
                        // `check_all=true` because there might be other known calls
                        // before that, due to the Uniswap V2 architecture.
                        true,
                    );

                    if let Some((idx_in, transfer_in)) = res {
                        let res = find_matching(
                            actions.iter().enumerate().skip(i + 1),
                            // Get a transfer
                            |t| t.transfer(),
                            // We just want the first transfer, no need to filter for anything
                            |_| true,
                            // `check_all = false` because the first known external call
                            // after the `swap` must be a transfer out
                            false,
                        );

                        if let Some((idx_out, transfer_out)) = res {
                            // change the action to a trade
                            *action = Classification::new(
                                Trade {
                                    t1: transfer_in.clone(),
                                    t2: transfer_out.clone(),
                                },
                                Vec::new(),
                            );
                            // if a trade has been made, then we will not try
                            // to flag this as "checked"
                            has_trade = true;
                            // prune the 2 trades
                            prune.push(idx_in);
                            prune.push(idx_out);
                        }
                    }
                } else if (call.call_type == CallType::StaticCall && preflight) || self.check(call)
                {
                    let protocol = uniswappy(&call);
                    inspection.protocols.insert(protocol);
                    *action = Classification::Prune;
                }
            }
        }

        prune
            .iter()
            .for_each(|p| inspection.actions[*p] = Classification::Prune);

        // If there are less than 2 classified actions (i.e. we didn't execute more
        // than 1 trade attempt, and if there were checked protocols
        // in this transaction, then that means there was an arb check which reverted early
        if inspection.protocols.len() > num_protocols
            && inspection
                .actions
                .iter()
                .filter_map(|x| x.as_action())
                .count()
                < 2
            && !has_trade
        {
            inspection.status = Status::Checked;
        }
    }
}

impl UniswapV3 {
    // Constructor
    pub fn new() -> Self {
        Self{
            router: BaseContract::from({
                serde_json::from_str::<Abi>(include_str!("../../abi/unirouterv3.json"))
                    .expect("could not parse uniswap abi")
            })
            pool: BaseContract::from({
                serde_json::from_str::<Abi>(include_str!("../../abi/unipair.json"))
                    .expect("could not parse uniswap abi")
            })
        }
    }
}