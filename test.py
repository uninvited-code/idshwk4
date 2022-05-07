@load base/frameworks/sumstats

event http_reply(c: connection, version: string, code: count, reason: string)
    {
    SumStats::observe("all_r",SumStats::Key($host=c$id$orig_h),[$str=c$http$uri]);
    if(code==404)
        SumStats::observe("bad_r",SumStats::Key($host=c$id$orig_h),[$str=c$http$uri]);
    }

event zeek_init()
    {
    local ar =SumStats::Reducer($stream="all_r", $apply=set(SumStats::SUM));
    local br = SumStats::Reducer($stream="bad_r", $apply=set(SumStats::SUM, SumStats::UNIQUE));
    SumStats::create([$name="404_founded",$epoch=10min,$reducers=set(ar,br),$epoch_result(ts: time, key: SumStats::Key,
    result: SumStats::Result)=
    {
    local a_r=result["all_r"];
    local b_r=result["bad_r"];
    if(b_r$sum>2&&(b_r$sum/a_r$sum)>0.2&&(b_r$unique/b_r$sum)>0.5)
        print fmt("%s is a scanner with %d scan attemps on %d urls", key$host, b_r$sum, b_r$unique);
    }]);
}
